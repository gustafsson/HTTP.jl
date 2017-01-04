@enum State Busy Idle Dead

"""
`HTTP.Connection`

Represents a persistent client connection to a remote host; only created
when a server response includes the "Connection: keep-alive" header. A connection
will be reused when sending subsequent requests to the same host.
"""
type Connection{I <: IO}
    tcp::I
    state::State
    statetime::DateTime
end

Connection(tcp::IO) = Connection(tcp, Busy, now(Dates.UTC))
busy!(conn::Connection) = (conn.state = conn.state == Dead ? (return nothing) : Busy; conn.statetime = now(Dates.UTC); return nothing)
idle!(conn::Connection) = (conn.state = conn.state == Dead ? (return nothing) : Idle; conn.statetime = now(Dates.UTC); return nothing)
dead!(conn::Connection) = (conn.state = Dead; conn.statetime = now(Dates.UTC); close(conn.tcp); return nothing)

"""
`HTTP.Client([logger::IO]; args...)`

A type to make connections to remote hosts, send HTTP requests, and manage state between requests.
Takes an optional `logger` IO argument where client activity is recorded (defaults to `STDOUT`).
Additional keyword arguments can be passed that will get transmitted with each HTTP request:

* `chunksize::Int`:
<!-- * `gzip::Bool`: -->
* `connecttimeout::Float64`: sets a timeout on how long to wait when trying to connect to a remote host; default = 10.0 seconds
* `readtimeout::Float64`: sets a timeout on how long to wait when receiving a response from a remote host; default = 9.0 seconds
* `tlsconfig::TLS.SSLConfig`: a valid `TLS.SSLConfig` which will be used to initialize every https connection
* `maxredirects::Int`:
"""
type Client{I <: IO}
    # connection pools for keep-alive; key is host
    httppool::Dict{String, Vector{Connection{TCPSocket}}}
    httpspool::Dict{String, Vector{Connection{TLS.SSLContext}}}
    # cookies are stored in-memory per host and automatically sent when appropriate
    cookies::Dict{String, Set{Cookie}}
    # buffer::Vector{UInt8} #TODO: create a fixed size buffer for reading bytes off the wire and having http_parser use, this should keep allocations down, need to make sure MbedTLS supports blocking readbytes!
    parser::Parser{ResponseParser}
    logger::I
    # global request settings
    options::RequestOptions
end

const DEFAULT_CHUNK_SIZE = 2^20
const DEFAULT_REQUEST_OPTIONS = (DEFAULT_CHUNK_SIZE, true, 10.0, 9.0, TLS.SSLConfig(true), 5)

Client(logger::IO, options::RequestOptions) = Client(Dict{String, Vector{Connection{TCPSocket}}}(), Dict{String, Vector{Connection{TLS.SSLContext}}}(), Dict{String, Set{Cookie}}(), Parser(Response), logger, options)
Client(logger::IO; args...) = Client(logger, RequestOptions(DEFAULT_REQUEST_OPTIONS...; args...))
Client(; args...) = Client(STDOUT, RequestOptions(DEFAULT_REQUEST_OPTIONS...; args...))

const DEFAULT_CLIENT = Client()

send!(request::Request; stream::Bool=false, verbose::Bool=true) = send!(DEFAULT_CLIENT, request; stream=stream, verbose=verbose)

function send!(client::Client, request::Request; history::Vector{Response}=Response[], stream::Bool=false, verbose::Bool=true)
    # ensure all Request options are set, using client.options if necessary
    # this works because request.options are null by default whereas client.options always have a default
    update!(request.options, client.options)
    return scheme(request.uri) == "http" ? send!(client, request, getconn(http, client, request , verbose), history, stream, verbose) :
                                           send!(client, request, getconn(https, client, request, verbose), history, stream, verbose)
end

Base.haskey(::Type{http}, client, host) = haskey(client.httppool, host)
Base.haskey(::Type{https}, client, host) = haskey(client.httpspool, host)

getconnections(::Type{http}, client, host) = client.httppool[host]
getconnections(::Type{https}, client, host) = client.httpspool[host]

setconnection!(::Type{http}, client, host, conn) = push!(get!(client.httppool, host, Connection[]), conn)
setconnection!(::Type{https}, client, host, conn) = push!(get!(client.httpspool, host, Connection[]), conn)

function getconn{S}(::Type{S}, client, request, verbose)
    # connect to remote host
    verbose && println(client.logger, "Connecting to remote host: $(request.uri)...")
    # check if an open connection to host already exists
    reused = false
    host = request.uri.host
    local conn::Connection{sockettype(S)}
    if haskey(S, client, host)
        conns = getconnections(S, client, host)
        inds = Int[]
        for (i, c) in enumerate(conns)
            if !isopen(c.tcp)
                dead!(c)
                push!(inds, i)
            elseif c.state == Idle
                busy!(c)
                verbose && println(client.logger, "Re-using existing connection to host...")
                conn, tcp = c, c.tcp
                reused = true
            end
        end
        deleteat!(conns, inds)
    end
    if !reused
        socket = @timeout request.options.connecttimeout Base.connect(Base.getaddrinfo(host), port(request.uri)) throw(TimeoutException(request.options.connecttimeout))
        # initialize TLS if necessary
        tcp = initTLS!(S, request, socket)
        conn = Connection(tcp)
        setconnection!(S, client, host, conn)
    end
    return conn
end

sockettype(::Type{http}) = TCPSocket
sockettype(::Type{https}) = TLS.SSLContext

initTLS!(::Type{http}, request, socket) = socket
function initTLS!(::Type{https}, request::Request, socket)
    stream = TLS.SSLContext()
    TLS.setup!(stream, request.options.tlsconfig)
    TLS.associate!(stream, socket)
    TLS.hostname!(stream, request.uri.host)
    TLS.handshake!(stream)
    return stream
end

function send!{T}(client, request, conn::Connection{T}, history, stream, verbose)
    host = request.uri.host
    # check if cookies should be added to outgoing request based on host
    if haskey(client.cookies, host)
        cookies = client.cookies[host]
        tosend = Set{Cookie}()
        expired = Set{Cookie}()
        for (i, cookie) in enumerate(cookies)
            if Cookies.shouldsend(cookie, scheme(request.uri) == "https", host, request.uri.path)
                cookie.expires != DateTime() && cookie.expires < now(Dates.UTC) && (push!(expired, cookie); continue)
                push!(tosend, cookie)
            end
        end
        setdiff!(client.cookies[host], expired)
        if length(tosend) > 0
            verbose && println(client.logger, "Adding cached cookie for host...")
            request.headers["Cookie"] = string(Base.get(request.headers, "Cookie", ""), [c for c in tosend])
        end
    end
    # send request over the wire
    verbose && println(client.logger, "Connected. Sending request...")
    verbose && show(client.logger, request)
    write(conn.tcp, request)
    # create a Response to fill
    response = Response(stream ? DEFAULT_CHUNK_SIZE : DEFAULT_MAX, request)
    client.parser.data.val = response
    verbose && print(client.logger, "\n\nSent. ")
    # process the response
    process!(client, conn, request, response, stream, verbose)
    !isempty(response.cookies) && union!(get!(client.cookies, host, Set{Cookie}()), response.cookies)
    # return immediately for streaming responses
    stream && return response
    verbose && println(client.logger, "Received response: ")
    verbose && show(client.logger, response); verbose && println(client.logger, "\n")
    # check for redirect
    response.history = history
    if request.method != "HEAD" && (300 <= status(response) < 400)
        key = haskey(response.headers, "Location") ? "Location" :
              haskey(response.headers, "location") ? "location" : ""
        if key != ""
            uri = URI(response.headers[key])
            uri = !isempty(uri.host) ? uri : URI(request.uri.scheme, request.uri.host, request.uri.port, uri.path, uri.query)
            push!(history, response)
            length(history) > request.options.maxredirects && throw(RedirectException(request.options.maxredirects))
            delete!(request.headers, "Host")
            delete!(request.headers, "Cookie")
            redirectreq = Request(request.method, uri, request.headers, request.body, request.options)
            verbose && println(client.logger, "Redirecting to $uri...")
            return send!(client, redirectreq, conn, history, false, verbose)
        end
    end
    return response
end

function process!(client, conn, request, response, stream, verbose)
    parser = client.parser.data
    while true
        # if no data after 30 seconds, break out
        verbose && println(client.logger, "Checking for response w/ read timeout of = $(request.options.readtimeout)...")
        buffer = @timeout request.options.readtimeout readavailable(conn.tcp) throw(TimeoutException(request.options.readtimeout))
        @debug(DEBUG, String(buffer))
        verbose && println(client.logger, "Received response bytes; processing...")
        http_parser_execute(client.parser, DEFAULT_RESPONSE_PARSER_SETTINGS, buffer, length(buffer))
        if errno(client.parser) != 0
            # TODO: error in parsing the http response
            break
        elseif parser.messagecomplete
            response.keepalive || dead!(conn)
            break
        elseif stream && parser.headerscomplete
            # async read the response body, returning the current response immediately
            response.bodytask = @async process!(client, conn, request, response, false, false)
            break
        end
        if !isopen(conn.tcp)
            dead!(conn)
            break
        end
    end
    !stream && idle!(conn)
    return nothing
end

immutable RedirectException <: Exception
    maxredirects::Int
end

function Base.show(io::IO, err::RedirectException)
    print(io, "RedirectException: more than $(err.maxredirects) redirects attempted")
end

immutable TimeoutException <: Exception
    timeout::Float64
end

function Base.show(io::IO, err::TimeoutException)
    print(io, "TimeoutException: server did not respond for more than $(err.timeout) seconds. ")
end

request!(method::String, uri::URI; args...) = request!(DEFAULT_CLIENT, method, uri; args...)

function request!(client::Client, method::String, uri::URI;
                    headers::Headers=Headers(),
                    body=Vector{UInt8}(),
                    stream::Bool=false,
                    verbose::Bool=true,
                    args...)
    request = Request(method, uri, headers, body, RequestOptions(; args...))
    send!(client, request; stream=stream, verbose=verbose)
end

for f in [:get, :post, :put, :delete, :head,
          :trace, :options, :patch, :connect]
    f_str = uppercase(string(f))
    @eval begin
        ($f)(uri::AbstractString; args...) = ($f)(URI(uri); args...)
        ($f)(uri::URI; args...) = request!(DEFAULT_CLIENT, $f_str, uri,; args...)
        ($f)(client::Client, uri::URI; args...) = request!(client, $f_str, uri,; args...)
    end
end
