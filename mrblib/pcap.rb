
ARPPacket = Struct.new(
    :ether_source,
    :ether_dest,
    :op, # :request / :reply
    :ipv4_source,
    :ipv4_dest
  )
