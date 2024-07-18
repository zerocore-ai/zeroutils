//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub struct Response {}

// let client: Client = ipc::Client::builder()
//     .path("some/path")
//     .build();

// // Parse

// let response: Response = client.action("open_at")
//     // .headers(...)
//     .body(OpenAtParams)
//     .send()
//     .await?;

// let t: EntityIdentifier = response.cbor().await?;

// // AsyncRead

// let response: Response = client.action("read_via_stream")
//     .body(cbor! { ... })
//     .send()
//     .await?;

// let mut buf = Vec::new();
// response.read(&mut buf).await;
