# Magic Tunnel Protocol

Check out the [`protocol.proto`] file for the core protocol types and
implementation suggestions.

The [`remote_config/`] directory shows an example integration, making use of
subtopics to enable future extensibility.

## Data Flow

This flow chart describes the data types and how they flow from the RC delivery
backend, to the ultimate integration handler that performs an action.

This describes the example use case of requesting an Agent debug "flare", an
action in the `REMOTE_CONFIG` namespace:

```mermaid
graph TD
    %% Nodes
    DD[DataDog Server]
    RC[RC Client]

    DH["<b>NAMESPACE_REMOTE_CONFIG</b><br/>Remote Config Dispatch Handler<br/><br/><i>deserializes payload as<br/><code>RemoteConfigRequest</code> to<br/>route to appropriate<br/>handler & gets handler<br/>response</i>"]

    FH[Flare Handler]

    %% Connections with Labels using <code> for monospacing
    DD -- "<code>MagicTunnelRequest{<br/>  correlation_id: 24,<br/>  namespace: NAMESPACE_REMOTE_CONFIG,<br/>  payload: &lt;RemoteConfigRequest bytes&gt;<br/>}</code>" --> RC

    RC -- "<code>MagicTunnelResponse{<br/>  correlation_id: 24,<br/>  result: response: &lt;RemoteConfigResponse bytes&gt;<br/>  OR<br/>  result: dispatch_error: DISPATCH_ERROR_...<br/>}</code>" --> DD

    RC -- "routes based on namespace<br/>& passes on <code>&lt;RemoteConfigRequest bytes&gt;</code>" --> DH

    DH -- "wraps <code>FlareResponse</code> in<br/><code>RemoteConfigResponse { subtopic: flare_response }</code>" --> RC

    DH -- "routes to handler using<br/>subtopic (oneof)<br/><br/><code>FlareRequest {...}</code>" --> FH

    FH -- "<code>FlareResponse{...}</code>" --> DH

    %% Styling
    style DH text-align:center
    style RC padding:10px
    style FH padding:10px
```

Integration teams implement and own the dispatch handler for their namespace,
and any subtopic handlers below it.
