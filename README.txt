[socket] [cmd] [sub-cmd] [args...]

class CommandCode {
public:
	static const int CommandEncrypt	=	100;
	static const int CommandDecrypt	=	101;

	static const int CommandBoot	=	200;
	static const int CommandCreateProfile	=	201;
	static const int CommandDeleteProfile	=	202;
	static const int CommandLock	=	203;
	static const int CommandUnlock	=	204;
};

class ResponseCode {
public:
    static const int CommandOkay              = 200;

    // 500 series - The command was not accepted and the requested
    // action did not take place.
    static const int CommandFailed = 400;
    static const int CommandParameterError = 401;
    static const int CommandNoPermission = 402;
    static const int CommandSyntaxError = 403;
    static const int CommandNotFound = 404;

};

# Run DEK daemon
obj/dekd [sock_path]

# Client test tool (Engine control)
obj/ndc [sock_path] [sock_name] [cmd] [cmd_code] [alias] ...

SDP engine add
[ctl] [201] [alias] [b64-pwd]
obj/ndc . dekd_ctl ctl 201 test_alias MTEyMTMxMzEz

SDP engine boot
[ctl] [200] [alias] 
obj/ndc . dekd_ctl ctl 200 test_alias

SDP engine lock 
[ctl] [203] [alias] 
obj/ndc . dekd_ctl ctl 203 test_alias

SDP engine unlock
[ctl] [204] [alias] [b64-pwd]
obj/ndc . dekd_ctl ctl 204 test_alias MTEyMTMxMzEz

SDP engine remove
[ctl] [202] [alias] 
obj/ndc . dekd_ctl ctl 202 test_alias


# Client test tool (enc/decru[t)

DEK encrypt
[enc] [100] [alias] [data]
obj/ndc . dekd_req enc 100 test_alias MTEyMTMxMzEz

@ result [resp_code] [ret] [alg] [edata] [tag] [pub-key] $
> ECDH encrypted : 
200 0 2 pJ9LCPXzJhdj MA/60z9r+I32W3ZpwWBNCw== BGzucWmo6eOOhpPpxaE1mEEKpiR9kSqLIMfVyFWOXx9y99aNgSAUVGTow0lX4yUdCM0k7o9shIxhJOD8hQg9Eww= $
> AES encrypted  : 
200 0 1 //Kk0bTx7hBJ of/Ogl9FuzYmRpA6XlKUzQ== ? $


DEK decrypt
[enc] [100] [alias] [alg] [edata] [tag] [pub-key] [$]
obj/ndc . dekd_req enc 101 test_alias 2 pJ9LCPXzJhdj MA/60z9r+I32W3ZpwWBNCw== BGzucWmo6eOOhpPpxaE1mEEKpiR9kSqLIMfVyFWOXx9y99aNgSAUVGTow0lX4yUdCM0k7o9shIxhJOD8hQg9Eww= $

obj/ndc . dekd_req enc 101 test_alias 1 //Kk0bTx7hBJ of/Ogl9FuzYmRpA6XlKUzQ== ? $

@result [resp_code] [ret] [data]
200 0 MTEyMTMxMzEz
