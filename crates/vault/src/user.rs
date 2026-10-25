//! Per-user key material lifecycle: register, unlock, password change, recovery (docs/02 §3.3).

use subtle::ConstantTimeEq;

use crate::{
    KdfParams, Mvk, SecretString, VaultError, aad, kdf,
    recovery::RecoveryKey,
    seal::{open_with, seal_with},
    secret::Key32,
};

/// Columns of `users` that hold key material. All values are safe to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserKeyRecord {
    pub kdf: KdfParams,
    pub kdf_salt: [u8; 16],
    pub auth_verifier: [u8; 32],
    pub mvk_nonce: [u8; 24],
    pub mvk_wrapped: Vec<u8>,
    pub rk_salt: [u8; 16],
    pub mvk_rk_nonce: [u8; 24],
    pub mvk_rk_wrapped: Vec<u8>,
}

/// Result of creating or recovering an account.
#[derive(Debug)]
pub struct Enrolled {
    pub record: UserKeyRecord,
    pub mvk: Mvk,
    /// Display form of the recovery key; show once, never store.
    pub recovery_key: SecretString,
}

fn mvk_aad(user_id: &str, purpose: &str) -> Vec<u8> {
    aad::encode(&[
        aad::LABEL_MVK_WRAP.as_bytes(),
        user_id.as_bytes(),
        purpose.as_bytes(),
    ])
}

struct PasswordWrap {
    kdf_salt: [u8; 16],
    auth_verifier: [u8; 32],
    mvk_nonce: [u8; 24],
    mvk_wrapped: Vec<u8>,
}

struct RecoveryWrap {
    rk_salt: [u8; 16],
    mvk_rk_nonce: [u8; 24],
    mvk_rk_wrapped: Vec<u8>,
    display: SecretString,
}

fn wrap_password(
    user_id: &str,
    mvk: &Mvk,
    password: &SecretString,
    params: KdfParams,
) -> Result<PasswordWrap, VaultError> {
    let kdf_salt = crate::random_array::<16>()?;
    let derived = kdf::derive(password, &kdf_salt, params)?;
    let sealed = seal_with(
        &derived.kek,
        &mvk_aad(user_id, "password"),
        mvk.0.as_bytes(),
    )?;
    Ok(PasswordWrap {
        kdf_salt,
        auth_verifier: derived.auth_verifier,
        mvk_nonce: sealed.nonce,
        mvk_wrapped: sealed.ciphertext,
    })
}

fn wrap_recovery(user_id: &str, mvk: &Mvk) -> Result<RecoveryWrap, VaultError> {
    let rk = RecoveryKey::generate()?;
    let rk_salt = crate::random_array::<16>()?;
    let sealed = seal_with(
        &rk.kek(&rk_salt)?,
        &mvk_aad(user_id, "recovery"),
        mvk.0.as_bytes(),
    )?;
    Ok(RecoveryWrap {
        rk_salt,
        mvk_rk_nonce: sealed.nonce,
        mvk_rk_wrapped: sealed.ciphertext,
        display: rk.display(),
    })
}

fn unwrap_mvk(
    key: &Key32,
    user_id: &str,
    purpose: &str,
    nonce: &[u8],
    wrapped: &[u8],
) -> Result<Mvk, VaultError> {
    let plain = open_with(key, &mvk_aad(user_id, purpose), nonce, wrapped)?;
    let bytes: [u8; 32] = plain
        .expose()
        .try_into()
        .map_err(|_| VaultError::Malformed("mvk length"))?;
    Ok(Mvk(Key32::from_array(bytes)))
}

/// Creates key material for a new account. Heavy (Argon2id): run on a blocking thread.
pub fn enroll(
    user_id: &str,
    password: &SecretString,
    params: KdfParams,
) -> Result<Enrolled, VaultError> {
    let mvk = Mvk(Key32::random()?);
    let pw = wrap_password(user_id, &mvk, password, params)?;
    let rk = wrap_recovery(user_id, &mvk)?;
    Ok(Enrolled {
        record: UserKeyRecord {
            kdf: params,
            kdf_salt: pw.kdf_salt,
            auth_verifier: pw.auth_verifier,
            mvk_nonce: pw.mvk_nonce,
            mvk_wrapped: pw.mvk_wrapped,
            rk_salt: rk.rk_salt,
            mvk_rk_nonce: rk.mvk_rk_nonce,
            mvk_rk_wrapped: rk.mvk_rk_wrapped,
        },
        mvk,
        recovery_key: rk.display,
    })
}

/// Verifies the password and unwraps the MVK.
pub fn unlock(
    user_id: &str,
    record: &UserKeyRecord,
    password: &SecretString,
) -> Result<Mvk, VaultError> {
    let derived = kdf::derive(password, &record.kdf_salt, record.kdf).map_err(|e| match e {
        VaultError::PasswordPolicy(_) => VaultError::InvalidCredentials,
        other => other,
    })?;
    if !bool::from(derived.auth_verifier.ct_eq(&record.auth_verifier)) {
        return Err(VaultError::InvalidCredentials);
    }
    unwrap_mvk(
        &derived.kek,
        user_id,
        "password",
        &record.mvk_nonce,
        &record.mvk_wrapped,
    )
}

/// Runs a full derivation against a fixed salt so unknown usernames cost the same as real ones.
pub fn burn_dummy(password: &SecretString, params: KdfParams) {
    let _ = kdf::derive(password, &[0x5Au8; 16], params);
}

/// New password wrap; MVK and recovery wrap unchanged. Returns the updated record.
pub fn change_password(
    user_id: &str,
    record: &UserKeyRecord,
    mvk: &Mvk,
    new_password: &SecretString,
    params: KdfParams,
) -> Result<UserKeyRecord, VaultError> {
    let pw = wrap_password(user_id, mvk, new_password, params)?;
    Ok(UserKeyRecord {
        kdf: params,
        kdf_salt: pw.kdf_salt,
        auth_verifier: pw.auth_verifier,
        mvk_nonce: pw.mvk_nonce,
        mvk_wrapped: pw.mvk_wrapped,
        ..record.clone()
    })
}

/// Replaces the recovery wrap with a freshly generated recovery key.
pub fn regenerate_recovery(
    user_id: &str,
    record: &UserKeyRecord,
    mvk: &Mvk,
) -> Result<(UserKeyRecord, SecretString), VaultError> {
    let rk = wrap_recovery(user_id, mvk)?;
    Ok((
        UserKeyRecord {
            rk_salt: rk.rk_salt,
            mvk_rk_nonce: rk.mvk_rk_nonce,
            mvk_rk_wrapped: rk.mvk_rk_wrapped,
            ..record.clone()
        },
        rk.display,
    ))
}

/// Recovery: RK unwraps the MVK, a new password wrap is created and the RK is rotated.
pub fn recover(
    user_id: &str,
    record: &UserKeyRecord,
    recovery_key: &SecretString,
    new_password: &SecretString,
    params: KdfParams,
) -> Result<Enrolled, VaultError> {
    kdf::normalize_password(new_password)?;
    let rk = RecoveryKey::parse(recovery_key)?;
    let mvk = unwrap_mvk(
        &rk.kek(&record.rk_salt)?,
        user_id,
        "recovery",
        &record.mvk_rk_nonce,
        &record.mvk_rk_wrapped,
    )
    .map_err(|e| {
        if e == VaultError::Integrity {
            VaultError::InvalidRecoveryKey
        } else {
            e
        }
    })?;
    let with_pw = change_password(user_id, record, &mvk, new_password, params)?;
    let (record, recovery_key) = regenerate_recovery(user_id, &with_pw, &mvk)?;
    Ok(Enrolled {
        record,
        mvk,
        recovery_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::RecordKind;

    const P: KdfParams = KdfParams::INSECURE_TEST;

    fn pw(s: &str) -> SecretString {
        SecretString::new(s.into())
    }

    #[test]
    fn enroll_unlock_and_reject_wrong_password() {
        let e = enroll("user-1", &pw("correct horse battery"), P).expect("enroll");
        assert_eq!(e.record.mvk_wrapped.len(), 48);
        assert_eq!(e.record.mvk_rk_wrapped.len(), 48);
        let sealed = e
            .mvk
            .seal(RecordKind::Secrets, "user-1", "node-1", b"s3cret")
            .expect("seal");

        let mvk = unlock("user-1", &e.record, &pw("correct horse battery")).expect("unlock");
        assert_eq!(
            mvk.open(
                RecordKind::Secrets,
                "user-1",
                "node-1",
                &sealed.nonce,
                &sealed.ciphertext
            )
            .expect("open")
            .expose(),
            b"s3cret"
        );

        assert_eq!(
            unlock("user-1", &e.record, &pw("wrong horse battery")).unwrap_err(),
            VaultError::InvalidCredentials
        );
        assert_eq!(
            unlock("user-1", &e.record, &pw("short")).unwrap_err(),
            VaultError::InvalidCredentials
        );
        // record bound to its user id
        assert!(unlock("user-2", &e.record, &pw("correct horse battery")).is_err());
    }

    #[test]
    fn password_change_keeps_mvk() {
        let e = enroll("u", &pw("first password 1"), P).expect("enroll");
        let sealed = e
            .mvk
            .seal(RecordKind::NodeMeta, "u", "n", b"meta")
            .expect("seal");
        let rec2 =
            change_password("u", &e.record, &e.mvk, &pw("second password 2"), P).expect("change");
        assert!(unlock("u", &rec2, &pw("first password 1")).is_err());
        let mvk = unlock("u", &rec2, &pw("second password 2")).expect("unlock");
        assert!(
            mvk.open(
                RecordKind::NodeMeta,
                "u",
                "n",
                &sealed.nonce,
                &sealed.ciphertext
            )
            .is_ok()
        );
        assert_eq!(rec2.mvk_rk_wrapped, e.record.mvk_rk_wrapped);
    }

    #[test]
    fn recovery_rotates_key_and_sets_new_password() {
        let e = enroll("u", &pw("forgotten password"), P).expect("enroll");
        let sealed = e
            .mvk
            .seal(RecordKind::Secrets, "u", "n", b"keep me")
            .expect("seal");
        let r = recover(
            "u",
            &e.record,
            &e.recovery_key,
            &pw("brand new password"),
            P,
        )
        .expect("recover");
        assert!(
            r.mvk
                .open(
                    RecordKind::Secrets,
                    "u",
                    "n",
                    &sealed.nonce,
                    &sealed.ciphertext
                )
                .is_ok()
        );
        assert!(unlock("u", &r.record, &pw("brand new password")).is_ok());
        assert_ne!(r.recovery_key.expose(), e.recovery_key.expose());
        // old recovery key no longer works
        assert_eq!(
            recover("u", &r.record, &e.recovery_key, &pw("another password!"), P).unwrap_err(),
            VaultError::InvalidRecoveryKey
        );
        // new one does
        assert!(recover("u", &r.record, &r.recovery_key, &pw("another password!"), P).is_ok());
    }

    #[test]
    fn recovery_with_other_users_key_fails() {
        let a = enroll("a", &pw("password for a!"), P).expect("enroll");
        let b = enroll("b", &pw("password for b!"), P).expect("enroll");
        assert_eq!(
            recover("a", &a.record, &b.recovery_key, &pw("new password a!"), P).unwrap_err(),
            VaultError::InvalidRecoveryKey
        );
    }
}
