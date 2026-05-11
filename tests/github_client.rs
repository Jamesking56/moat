use moat::support::github::{Client, Fetch};
use serde::Deserialize;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Deserialize, Debug, PartialEq)]
struct User {
    login: String,
}

fn client(server: &MockServer) -> Client {
    Client::with_base_url("test-token".into(), server.uri()).unwrap()
}

#[tokio::test]
async fn get_json_sends_bearer_auth_and_api_version_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/octocat"))
        .and(header("authorization", "Bearer test-token"))
        .and(header("accept", "application/vnd.github+json"))
        .and(header("x-github-api-version", "2022-11-28"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "login": "octocat" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let c = client(&server);
    let got = c.get_json::<User>("/users/octocat").await.unwrap();
    match got {
        Fetch::Ok(u) => assert_eq!(u.login, "octocat"),
        _ => panic!("expected Ok"),
    }
}

#[tokio::test]
async fn get_json_maps_404_to_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/nope"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let c = client(&server);
    assert!(matches!(
        c.get_json::<User>("/users/nope").await.unwrap(),
        Fetch::NotFound
    ));
}

#[tokio::test]
async fn get_json_maps_403_and_422_to_forbidden() {
    for status in [403u16, 422] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let c = client(&server);
        assert!(matches!(
            c.get_json::<User>("/x").await.unwrap(),
            Fetch::Forbidden
        ));
    }
}

#[tokio::test]
async fn get_json_propagates_unexpected_status_as_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/boom"))
        .respond_with(ResponseTemplate::new(500).set_body_string("kapow"))
        .mount(&server)
        .await;
    let c = client(&server);
    let err = c.get_json::<User>("/boom").await.unwrap_err();
    assert!(err.to_string().contains("500"));
    assert!(err.to_string().contains("kapow"));
}

#[tokio::test]
async fn get_presence_distinguishes_ok_notfound_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/forbid"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let c = client(&server);
    assert!(matches!(
        c.get_presence("/ok").await.unwrap(),
        Fetch::Ok(())
    ));
    assert!(matches!(
        c.get_presence("/missing").await.unwrap(),
        Fetch::NotFound
    ));
    assert!(matches!(
        c.get_presence("/forbid").await.unwrap(),
        Fetch::Forbidden
    ));
}

#[tokio::test]
async fn get_paginated_collects_pages_via_link_header() {
    let server = MockServer::start().await;
    let base = server.uri();
    let link_page2 = format!(r#"<{base}/items?per_page=100&page=2>; rel="next""#);

    Mock::given(method("GET"))
        .and(path("/items"))
        .and(query_param("per_page", "100"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", link_page2.as_str())
                .set_body_json(serde_json::json!([{ "login": "a" }, { "login": "b" }])),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/items"))
        .and(query_param("page", "2"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([{ "login": "c" }])),
        )
        .mount(&server)
        .await;

    let c = client(&server);
    match c.get_paginated::<User>("/items").await.unwrap() {
        Fetch::Ok(v) => assert_eq!(
            v.iter().map(|u| u.login.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        ),
        _ => panic!("expected Ok"),
    }
}

#[tokio::test]
async fn get_paginated_appends_per_page_to_existing_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/things"))
        .and(query_param("filter", "x"))
        .and(query_param("per_page", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    assert!(matches!(
        c.get_paginated::<User>("/things?filter=x").await.unwrap(),
        Fetch::Ok(_)
    ));
}

#[tokio::test]
async fn get_paginated_maps_first_page_403_to_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/items"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let c = client(&server);
    assert!(matches!(
        c.get_paginated::<User>("/items").await.unwrap(),
        Fetch::Forbidden
    ));
}

#[tokio::test]
async fn get_paginated_maps_first_page_404_to_notfound() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/items"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let c = client(&server);
    assert!(matches!(
        c.get_paginated::<User>("/items").await.unwrap(),
        Fetch::NotFound
    ));
}
