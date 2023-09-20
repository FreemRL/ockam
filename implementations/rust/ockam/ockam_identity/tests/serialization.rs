use ockam_core::Result;
use ockam_identity::models::CredentialSchemaIdentifier;
use ockam_identity::utils::AttributesBuilder;
use ockam_identity::{identities, MAX_CREDENTIAL_VALIDITY};

#[tokio::test]
async fn identity() -> Result<()> {
    let identities = identities();
    let identities_creation = identities.identities_creation();

    let identity = identities_creation.create_identity().await?;

    let identity = identity.export()?;

    println!("{}", hex::encode(identity));

    Ok(())
}

#[tokio::test]
async fn sc_purpose_key() -> Result<()> {
    let identities = identities();
    let identities_creation = identities.identities_creation();

    let identity = identities_creation.create_identity().await?;

    let purpose_key = identities
        .purpose_keys()
        .secure_channel_purpose_keys_creation()
        .create_purpose_key(identity.identifier())
        .await?;

    let purpose_key = minicbor::to_vec(purpose_key.attestation())?;

    println!("{}", hex::encode(purpose_key));

    Ok(())
}

#[tokio::test]
async fn credential_and_purpose_key() -> Result<()> {
    let identities = identities();
    let identities_creation = identities.identities_creation();

    let identity = identities_creation.create_identity().await?;

    let attributes = AttributesBuilder::with_schema(CredentialSchemaIdentifier(1))
        .with_attribute(b"trust_context_it".to_vec(), b"889255db".to_vec())
        .build();
    let credential = identities
        .credentials()
        .credentials_creation()
        .issue_credential(
            identity.identifier(),
            identity.identifier(),
            attributes,
            MAX_CREDENTIAL_VALIDITY,
        )
        .await?;

    let credential = minicbor::to_vec(credential)?;
    println!("{}", hex::encode(credential));

    Ok(())
}
