//! Route table: `/login` vs the guarded `/` shell (`/` flows, `/alerts` alerts).

use leptos::prelude::*;
use leptos_router::components::{ParentRoute, Route, Router, Routes};
use leptos_router::path;

use crate::state::AppState;
use crate::views::{AlertsView, FlowsView, LoginView, Shell};

/// Top-level component: provides shared state and renders the route table.
#[component]
pub fn App() -> impl IntoView {
    provide_context(AppState::new());
    view! {
        <Router>
            <Routes fallback=|| view! { <p class="muted">"Not found."</p> }>
                <Route path=path!("/login") view=LoginView />
                <ParentRoute path=path!("/") view=Shell>
                    <Route path=path!("") view=FlowsView />
                    <Route path=path!("alerts") view=AlertsView />
                </ParentRoute>
            </Routes>
        </Router>
    }
}
