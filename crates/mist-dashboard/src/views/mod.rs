//! View components: login form, app shell, overview, flows table, alerts list.

pub(crate) mod alerts;
pub(crate) mod charts;
mod flows;
mod login;
mod overview;
mod shell;

pub use alerts::AlertsView;
pub use flows::FlowsView;
pub use login::LoginView;
pub use overview::OverviewView;
pub use shell::Shell;
