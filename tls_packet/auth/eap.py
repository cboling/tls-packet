class EAPOLPacketType:
    """
    This field is one octet in length. Table 11-3 lists the Packet Types specified by this standard, clause(s) that
    specify Packet Body encoding, decoding, and validation for each type, and the protocol entities that are the
    intended recipients. All other possible values of the Packet Type shall not be used: they are reserved for
    future extensions. To ensure that backward compatibility is maintained for future versions, validation, and
    protocol version handling for all types of EAPOL PDUs shall follow certain general rules (11.4, 11.5).
    """
    EAP_EAP = 0
    EAPOL_Start = 1
    EAPOL_Logoff = 2
    EAPOL_Key = 3
    EAPOL_Encapsulated_ASF_Alert = 4
    EAPOL_MKA = 5
    EAPOL_Announcment_Generic = 6
    EAPOL_Announcment_Specific = 7
    EAPOL_Announcment_REQ = 8


eap_code = {
    "Request":  1,
    "Response": 2,
    "Success":  3,
    "Failure":  4,
    "Initiate": 5,
    "Finish":   6
}
