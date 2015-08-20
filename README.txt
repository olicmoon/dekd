[socket] [cmd] [sub-cmd] [args...]

command code :
100 : encrypt
101 : decrypt

response code :
200 : success
300 : error

> dekd_req [enc] [0:encrypt] [data]
< 200 [alg] [edata] [tag] [pubkey] $
< 300 //on failure

> dekd_req [enc] [1:decrypt] [alg] [edata] [tag] [pubkey] $
< 200 [data]
< 300 //on failure

alg : [0:plain] [1:AES] [2:RSA] [3:ECDH]

e.i) AES encrypted data
dekd_req enc [1:decrypt] [1:alg] ["xyz":edata] ["?":tag] ["?":pubkey] $
enc 1 1 q7HuZn3Ok/1sA4znrAYz7UqArQ3H5NKTJD7HXq7d2A5nV1sRdDlKnz+92i+Fb5o= ? ? $

e.i) ECDH encrypted data
dekd_req enc [1:decrypt] [3:alg] ["xyz":edata] ["abc":tag] ["qwe":pubkey] $
enc 1 3 q7HuZn3Ok/1sA4znrAYz7UqArQ3H5NKTJD7HXq7d2A5nV1sRdDlKnz+92i+Fb5o= /KDFwFJL7nZz+HrUxtCCJw== BLDRqg6R+v+5QgmDJo4GnW/oHXIRqjeTnFHwV6j0aG5/w8jdLVaeURyO+1gMszfpmDrgTao3dxn4U5LcGG0Mj2I= $



