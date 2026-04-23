use axum::response::Html;

const HTML: &str = include_str!("../static/dashboard.html");

pub async fn serve() -> Html<&'static str> {
    Html(HTML)
}
