//! View components: login form, app shell, flows table, alerts list.

mod alerts;
mod flows;
mod login;
mod shell;

pub use alerts::AlertsView;
pub use flows::FlowsView;
pub use login::LoginView;
pub use shell::Shell;
