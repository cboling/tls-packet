# tls_packet
Python TLS Packet decoder/serializer library with a focus on TLS packets used during 
IEEE 802.1x/RADIUS interactions

The initial target is a TLSv1.2 with emphasis on the TLS Client Side operations.  Once it
is successfully working against a FreeRADIUS v3.0+ server, other TLS vesions (particularly v1.3)
will be supported.

In addition, a goal once it works with FreeRADIUS as a client, creating the TLS Server side to work
without a FreeRADIUS server is a goal.

Another future goal is to provide some decode options similar to what go-packet provides so that
the users can tune for the performance they need.

## Release History

| Version | Notes                                                      |
|:-------:|:-----------------------------------------------------------|
|  0.0.1  | Initial build to get package installation scripts together |
