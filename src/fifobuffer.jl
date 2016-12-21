"""
A `FIFOBuffer` is a first-in, first-out in-memory IO buffer type

Constructors:
`FIFOBuffer([max])`: creates a `FIFOBuffer` with a maximum size of `max`; this means that bytes can be written
up until `max` number of bytes have been written (with none being read). At this point, the `FIFOBuffer` is full
and will return 0 for all subsequent writes. If no `max` argument is given, then an "infinite" size `FIFOBuffer` is returned;
this essentially allows all writes every time.

Reading is supported via `readavailable`, which "extracts" all bytes that have been written; it also
calls `notify` on the `FIFOBuffer`'s internal `cond::Condition`. This allows writers a workflow like:

```julia
while true
    nb = write(fifo, bytes)
    nb == 0 && wait(fifo)
    bytes = getmorebytes()
end
```

Writing also calls `notify` on the condition, so readers can operate like:

```julia
while !eof(fifo)
    bytes = readavailable(fifo)
    if isempty(bytes)
        wait(fifo)
    else
        dosomethingwithbytes(bytes)
    end
end
```
"""
type FIFOBuffer <: IO
    len::Int # length of buffer in bytes
    max::Int # the max size buffer is allowed to grow to
    nb::Int  # number of bytes available to read in buffer
    f::Int   # buffer index that should be read next, unless nb == 0, then buffer is empty
    l::Int   # buffer index that should be written to next, unless nb == len, then buffer is full
    buffer::Vector{UInt8}
    cond::Condition
    task::Task
    eof::Bool
end

const DEFAULT_MAX = Int(typemax(Int32))^2

FIFOBuffer(max) = FIFOBuffer(0, max, 0, 1, 1, UInt8[], Condition(), current_task(), false)
FIFOBuffer() = FIFOBuffer(DEFAULT_MAX)

Base.length(f::FIFOBuffer) = f.nb
Base.wait(f::FIFOBuffer) = wait(f.cond)
function Base.eof(f::FIFOBuffer)
    if current_task() == f.task
        # not asynchronous, just read until buffer is empty
        return f.nb == 0
    else
        # if being called asynchronously, allow user
        # to set eof by calling `eof!`
        return f.eof
    end
end
function eof!(f::FIFOBuffer)
    f.eof = true
    notify(f.cond)
    return
end

# 0 | 1 | 2 | 3 | 4 | 5 |
#---|---|---|---|---|---|
#   |f/l| _ | _ | _ | _ | empty, f == l, nb = 0, can't read, can write from l to l-1, don't need to change f, l = l, nb = len
#   | _ | _ |f/l| _ | _ | empty, f == l, nb = 0, can't read, can write from l:end, 1:l-1, don't need to change f, l = l, nb = len
#   | _ | f | x | l | _ | where f < l, can read f:l-1, then set f = l, can write l:end, 1:f-1, then set l = f, nb = len
#   | l | _ | _ | f | x | where l < f, can read f:end, 1:l-1, can write l:f-1, then set l = f
#   |f/l| x | x | x | x | full l == f, nb = len, can read f:l-1, can't write
#   | x | x |f/l| x | x | full l == f, nb = len, can read f:end, 1:l-1, can't write
function Base.readavailable(f::FIFOBuffer)
    # no data to read
    if f.nb == 0
        if current_task() == f.task
            return UInt8[]
        else # async: block till there's data to read
            wait(f.cond)
            f.nb == 0 && return UInt8[]
        end
    end
    if f.f < f.l
        @inbounds bytes = f.buffer[f.f:f.l-1]
    else
        # we've wrapped around
        @inbounds bytes = f.buffer[f.f:end]
        @inbounds append!(bytes, view(f.buffer, 1:f.l-1))
    end
    f.f = f.l
    f.nb = 0
    notify(f.cond)
    return bytes
end

# read at most `nb` bytes
function Base.readbytes(f::FIFOBuffer, nb)
    # no data to read
    if f.nb == 0
        if current_task() == f.task
            return UInt8[]
        else # async: block till there's data to read
            wait(f.cond)
            f.nb == 0 && return UInt8[]
        end
    end
    if f.f < f.l
        l = (f.l - f.f) <= nb ? (f.l - 1) : (f.f + nb - 1)
        @inbounds bytes = f.buffer[f.f:l]
        f.f = mod1(l + 1, f.max)
    else
        # we've wrapped around
        if nb <= (f.len - f.f + 1)
            # we can read all we need between f.f and f.len
            @inbounds bytes = f.buffer[f.f:(f.f + nb - 1)]
            f.f = mod1(f.f + nb, f.max)
        else
            @inbounds bytes = f.buffer[f.f:f.len]
            l = min(f.l - 1, nb - length(bytes))
            @inbounds append!(bytes, view(f.buffer, 1:l))
            f.f = mod1(l + 1, f.max)
        end
    end
    f.nb -= length(bytes)
    notify(f.cond)
    return bytes
end

function Base.read(f::FIFOBuffer, ::Type{UInt8})
    f.nb == 0 && return 0x00, false
    # data to read
    @inbounds b = f.buffer[f.f]
    f.f = mod1(f.f + 1, f.max)
    f.nb -= 1
    notify(f.cond)
    return b, true
end

function Base.String(f::FIFOBuffer)
    f.nb == 0 && return ""
    if f.f < f.l
        return String(f.buffer[f.f:f.l-1])
    else
        bytes = f.buffer[f.f:end]
        append!(bytes, view(f.buffer, 1:f.l-1))
        return String(bytes)
    end
end

function Base.write(f::FIFOBuffer, b::UInt8)
    # buffer full, check if we can grow it
    if f.nb == f.len || f.len < f.l
        if f.len < f.max
            push!(f.buffer, 0x00)
            f.len += 1
        else
            return 0
        end
    end
    # write our byte
    @inbounds f.buffer[f.l] = b
    f.l = mod1(f.l + 1, f.max)
    f.nb += 1
    notify(f.cond)
    return 1
end

function Base.write(f::FIFOBuffer, bytes::Vector{UInt8})
    # buffer full, check if we can grow it
    len = length(bytes)
    if f.nb == f.len || f.len < f.l
        if f.len < f.max
            append!(f.buffer, zeros(UInt8, min(len, f.max - f.len)))
            f.len = length(f.buffer)
        else
            if current_task() == f.task
                return 0
            else # async: block until there's room to write
                wait(f.cond)
                f.nb == f.len && return 0
            end
        end
    end
    if f.f <= f.l
        # non-wraparound
        avail = f.len - f.l + 1
        if len > avail
            # need to wrap around, and check if there's enough room to write full bytes
            # write `avail` # of bytes to end of buffer
            unsafe_copy!(f.buffer, f.l, bytes, 1, avail)
            if len - avail < f.f
                # there's enough room to write the rest of bytes
                unsafe_copy!(f.buffer, 1, bytes, avail + 1, len - avail)
                f.l = len - avail + 1
            else
                # not able to write all of bytes
                unsafe_copy!(f.buffer, 1, bytes, avail + 1, f.f - 1)
                f.l = f.f
                f.nb += avail + f.f - 1
                notify(f.cond)
                return avail + f.f - 1
            end
        else
            # there's enough room to write bytes through the end of the buffer
            unsafe_copy!(f.buffer, f.l, bytes, 1, len)
            f.l = mod1(f.l + len, f.max)
        end
    else
        # already in wrap-around state
        if len > mod1(f.f - f.l, f.max)
            # not able to write all of bytes
            unsafe_copy!(f.buffer, 1, bytes, 1, f.f - f.l)
            f.l = f.f
            f.nb += f.f - f.l
            notify(f.cond)
            return f.f - f.l
        else
            # there's enough room to write bytes
            unsafe_copy!(f.buffer, f.l, bytes, 1, len)
            f.l  = mod1(f.l + len, f.max)
        end
    end
    f.nb += len
    notify(f.cond)
    return len
end
