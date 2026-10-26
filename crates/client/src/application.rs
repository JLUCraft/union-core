//! One organization application: activities, competitions, files, and approvals share one journal.
pub type Application = flows::Flows<events::EventsDomain>;
pub type Input = crate::generic::Input<Application>;
pub type Snapshot = state::State<Application>;
pub type Action = state::governance::Action<Application>;
pub type Authority = authority::authority::Authority<Application>;

pub fn competition(action: league::LeagueAction) -> Action {
    Action::Domain(flows::FlowAction::Inner(events::EventAction::Competition(
        action,
    )))
}
pub async fn execute(
    identity: crate::Identity,
    input: Input,
) -> crate::Result<crate::journal::Response<Application>> {
    crate::generic::execute(identity, input, crate::journal::PROTOCOL).await
}
