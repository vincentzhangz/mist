//! `/login`: email + password form, stores the JWT on success.

use leptos::html::Input;
use leptos::prelude::*;
use leptos_router::components::Redirect;

use crate::api::login;
use crate::state::AppState;

/// Email + password form. On success stores the token; the guard below then
/// redirects to `/`.
#[component]
pub fn LoginView() -> impl IntoView {
    let state = expect_context::<AppState>();
    let email_ref = NodeRef::<Input>::new();
    let password_ref = NodeRef::<Input>::new();
    let error = RwSignal::new(Option::<String>::None);
    let busy = RwSignal::new(false);

    view! {
        <Show
            when=move || state.token.get().is_none()
            fallback=|| {
                view! { <Redirect path="/" /> }
            }
        >
            <main class="login-page">
                <form
                    class="login-card"
                    on:submit=move |ev: leptos::ev::SubmitEvent| {
                        ev.prevent_default();
                        if busy.get_untracked() {
                            return;
                        }
                        let email = email_ref
                            .get_untracked()
                            .map(|el| el.value())
                            .unwrap_or_default();
                        let password = password_ref
                            .get_untracked()
                            .map(|el| el.value())
                            .unwrap_or_default();
                        if email.trim().is_empty() || password.is_empty() {
                            error.set(
                                Some("Email and password are required.".to_owned()),
                            );
                            return;
                        }
                        busy.set(true);
                        error.set(None);
                        leptos::task::spawn_local(async move {
                            match login(email.trim(), &password).await {
                                Ok(resp) => {
                                    state.set_session(resp.token, resp.email);
                                }
                                Err(err) => {
                                    error.set(Some(err.to_string()));
                                }
                            }
                            busy.set(false);
                        });
                    }
                >
                    <h1>"mist"</h1>
                    <p class="muted">"Sign in to the network dashboard"</p>
                    <label>
                        "Email"
                        <input
                            type="email"
                            name="email"
                            placeholder="admin@example.com"
                            autocomplete="username"
                            node_ref=email_ref
                        />
                    </label>
                    <label>
                        "Password"
                        <input
                            type="password"
                            name="password"
                            placeholder="••••••••"
                            autocomplete="current-password"
                            node_ref=password_ref
                        />
                    </label>
                    <Show when=move || error.get().is_some()>
                        <p class="error" aria-live="polite">
                            {move || error.get().unwrap_or_default()}
                        </p>
                    </Show>
                    <button type="submit" disabled=move || busy.get()>
                        {move || if busy.get() { "Signing in…" } else { "Sign in" }}
                    </button>
                </form>
            </main>
        </Show>
    }
}
