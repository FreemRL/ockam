use ockam_core::Result;
use ockam_identity::models::SchemaId;
use ockam_identity::utils::AttributesBuilder;
use ockam_identity::{Identities, Purpose, Vault};
use ockam_vault::{SecretAttributes, SecretType, SigningVault};
use ockam_vault_aws::AwsSigningVault;
use std::sync::Arc;
use std::time::Duration;

/// These tests needs to be executed with the following environment variables
/// AWS_REGION
/// AWS_ACCESS_KEY_ID
/// AWS_SECRET_ACCESS_KEY
/// or credentials in ~/.aws/credentials

#[tokio::test]
#[ignore]
async fn create_identity_with_aws_pregenerated_key() -> Result<()> {
    let mut vault = Vault::create();
    let aws_vault = Arc::new(AwsSigningVault::create().await?);
    vault.identity_vault = aws_vault.clone();
    let identities = Identities::builder().with_vault(vault.clone()).build();

    // create a secret key using the AWS KMS
    let key_id = aws_vault.generate_key(SecretAttributes::NistP256).await?;

    let identity = identities
        .identities_creation()
        .identity_builder()
        .with_existing_key(key_id.clone(), SecretType::NistP256)
        .build()
        .await?;

    identities
        .identities_creation()
        .import(Some(identity.identifier()), &identity.export()?)
        .await?;

    aws_vault.delete_key(key_id).await?;

    Ok(())
}

#[tokio::test]
#[ignore]
async fn create_identity_with_aws_random_key() -> Result<()> {
    let mut vault = Vault::create();
    let aws_vault = Arc::new(AwsSigningVault::create().await?);
    vault.identity_vault = aws_vault.clone();
    let identities = Identities::builder().with_vault(vault.clone()).build();

    let identity = identities
        .identities_creation()
        .identity_builder()
        .with_random_key(SecretType::NistP256)
        .build()
        .await?;

    identities
        .identities_creation()
        .import(Some(identity.identifier()), &identity.export()?)
        .await?;

    let key = identities
        .identities_keys()
        .get_secret_key(&identity)
        .await?;

    aws_vault.delete_key(key).await?;

    Ok(())
}

#[tokio::test]
#[ignore]
async fn create_credential_aws_key() -> Result<()> {
    let mut vault = Vault::create();
    let aws_vault = Arc::new(AwsSigningVault::create().await?);
    vault.credential_vault = aws_vault.clone();
    let identities = Identities::builder().with_vault(vault.clone()).build();

    let identity = identities.identities_creation().create_identity().await?;

    let purpose_key = identities
        .purpose_keys()
        .purpose_keys_creation()
        .purpose_key_builder(identity.identifier(), Purpose::Credentials)
        .with_random_key(SecretType::NistP256)
        .build()
        .await?;

    identities
        .purpose_keys()
        .purpose_keys_verification()
        .verify_purpose_key_attestation(Some(identity.identifier()), purpose_key.attestation())
        .await?;

    let attributes = AttributesBuilder::with_schema(SchemaId(1))
        .with_attribute(*b"key", *b"value")
        .build();

    let credential = identities
        .credentials()
        .credentials_creation()
        .issue_credential(
            identity.identifier(),
            identity.identifier(),
            attributes,
            Duration::from_secs(120),
        )
        .await?;

    identities
        .credentials()
        .credentials_verification()
        .verify_credential(
            Some(identity.identifier()),
            &[identity.identifier().clone()],
            &credential,
        )
        .await?;

    aws_vault.delete_key(purpose_key.key_id().clone()).await?;

    Ok(())
}
