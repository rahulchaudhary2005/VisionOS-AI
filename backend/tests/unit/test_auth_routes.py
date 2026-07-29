def test_register_and_login_flow(client):
    payload = {
        "email": "routeuser@example.com",
        "password": "Str0ngP@ssword1",
        "full_name": "Route User",
    }

    register_response = client.post("/api/v1/auth/register", json=payload)
    assert register_response.status_code == 200
    data = register_response.json()
    assert data["success"] is True
    assert isinstance(data["user_id"], str)

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )
    assert login_response.status_code == 200
    login_data = login_response.json()
    assert login_data["success"] is True
    assert login_data["tokens"]["access_token"]
    assert login_data["tokens"]["refresh_token"]


def test_refresh_endpoint_returns_new_token(client):
    payload = {
        "email": "refreshroute@example.com",
        "password": "Str0ngP@ssword1",
        "full_name": "Refresh Route",
    }

    client.post("/api/v1/auth/register", json=payload)
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )
    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": login_response.json()["tokens"]["refresh_token"]},
    )

    assert refresh_response.status_code == 200
    refresh_data = refresh_response.json()
    assert refresh_data["tokens"]["access_token"]
    assert refresh_data["tokens"]["refresh_token"]
    assert (
        refresh_data["tokens"]["access_token"]
        != login_response.json()["tokens"]["access_token"]
    )
