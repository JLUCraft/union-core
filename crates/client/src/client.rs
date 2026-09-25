//! League deployment facade. Other domains use generic::execute.
pub type Input = crate::generic::Input<league::LeagueDomain>;
pub async fn execute(
    identity: crate::Identity,
    input: Input,
) -> crate::Result<crate::journal::Response<league::LeagueDomain>> {
    crate::generic::execute(identity, input).await
}
