BITS=512
# OTA server expects a key with exponent 3
openssl genrsa -out priv.key -3 $BITS
openssl rsa -in priv.key -pubout -out pub.key
openssl pkey -in priv.key -text

python -c "import rsa_sign; rsa_sign.dump_c(rsa_sign.load_key())"