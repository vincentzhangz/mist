//! mist-dashboard: Leptos 0.8 CSR single-page app.
//!
//! Routes: `/login` (email + password) and `/` (guarded app shell with the
//! flows and alerts views). The API serves this bundle at `/` in production.

mod api;
mod app;
mod dto;
mod state;
mod views;

use app::App;

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}
