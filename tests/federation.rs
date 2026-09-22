use union_core::{Identity, federation::*};
#[test]
fn delegated_email_issuer_cannot_elevate_school_or_holder() -> Result<(), Box<dyn std::error::Error>>
{
    let root = Identity::generate();
    let issuer = Identity::generate();
    let holder = Identity::generate();
    let delegation = delegate(
        &root,
        StudentDelegation {
            id: "delegation".into(),
            school: "jlu".into(),
            issuer: issuer.peer_id().to_string(),
            not_before: 10,
            expires_at: 1000,
            max_credential_seconds: 100,
            evidence: vec![Evidence::InstitutionalEmail],
        },
    )?;
    let claims = StudentClaims {
        id: "student".into(),
        school: "jlu".into(),
        subject: "student-opaque-id".into(),
        game_profile: "profile".into(),
        holder: holder.peer_id().to_string(),
        evidence: Evidence::InstitutionalEmail,
        verified_at: 20,
        issued_at: 20,
        expires_at: 100,
    };
    let credential = issue(&issuer, delegation.clone(), claims.clone())?;
    let mut policy = TrustPolicy {
        local_school: "jlu".into(),
        province_schools: Default::default(),
        mua_schools: ["jlu".into()].into(),
        school_roots: [("jlu".into(), [root.peer_id().to_string()].into())].into(),
        revoked: Default::default(),
        max_verification_age_seconds: 200,
    };
    assert_eq!(
        policy
            .verify(&credential, holder.peer_id(), "profile", 30)?
            .0,
        Circle::Local
    );
    policy.local_school = "other".into();
    assert_eq!(
        policy
            .verify(&credential, holder.peer_id(), "profile", 30)?
            .0,
        Circle::Mua
    );
    policy.province_schools.insert("jlu".into());
    assert_eq!(
        policy
            .verify(&credential, holder.peer_id(), "profile", 30)?
            .0,
        Circle::Province
    );
    assert!(
        policy
            .verify(&credential, issuer.peer_id(), "profile", 30)
            .is_err()
    );
    let mut forged = claims;
    forged.school = "other".into();
    let forged = issue(&issuer, delegation, forged)?;
    assert!(
        policy
            .verify(&forged, holder.peer_id(), "profile", 30)
            .is_err()
    );
    policy.revoked.insert("delegation".into());
    assert!(
        policy
            .verify(&credential, holder.peer_id(), "profile", 30)
            .is_err()
    );
    Ok(())
}

#[test]
fn mua_account_and_alumni_never_imply_current_student() -> Result<(), Box<dyn std::error::Error>> {
    let root = Identity::generate();
    let issuer = Identity::generate();
    let holder = Identity::generate();
    let delegation = delegate(
        &root,
        StudentDelegation {
            id: "d".into(),
            school: "jlu".into(),
            issuer: issuer.peer_id().to_string(),
            not_before: 0,
            expires_at: 1000,
            max_credential_seconds: 1000,
            evidence: vec![
                Evidence::MuaAccountOnly,
                Evidence::Alumni,
                Evidence::InstitutionalEmail,
                Evidence::CurrentEnrollment,
            ],
        },
    )?;
    let policy = TrustPolicy {
        local_school: "jlu".into(),
        province_schools: Default::default(),
        mua_schools: Default::default(),
        school_roots: [("jlu".into(), [root.peer_id().to_string()].into())].into(),
        revoked: Default::default(),
        max_verification_age_seconds: 1000,
    };
    for evidence in [
        Evidence::MuaAccountOnly,
        Evidence::Alumni,
        Evidence::InstitutionalEmail,
        Evidence::CurrentEnrollment,
    ] {
        let credential = issue(
            &issuer,
            delegation.clone(),
            StudentClaims {
                id: "s".into(),
                school: "jlu".into(),
                subject: "MUA:123".into(),
                game_profile: "uuid".into(),
                holder: holder.peer_id().to_string(),
                evidence,
                verified_at: 10,
                issued_at: 10,
                expires_at: 100,
            },
        )?;
        let expected = if matches!(evidence, Evidence::MuaAccountOnly | Evidence::Alumni) {
            Circle::Unknown
        } else {
            Circle::Local
        };
        assert_eq!(
            policy.verify(&credential, holder.peer_id(), "uuid", 20)?.0,
            expected
        );
        assert_eq!(
            policy
                .verify_current_student(&credential, holder.peer_id(), "uuid", 20)
                .is_ok(),
            evidence == Evidence::CurrentEnrollment
        );
    }
    Ok(())
}
