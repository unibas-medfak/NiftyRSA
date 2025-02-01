openssl req -x509 -newkey rsa:2048 -subj "/O=Uni Basel/OU=Medizin/CN=Nifty RSA/" -passout pass:"secret" -keyout delete.me -outform der -out base64-X509-public-key.der -days 3650

openssl x509 -noout -text -in base64-X509-public-key.der

base64 -i base64-X509-public-key.der -o base64-X509-public-key.txt

rm base64-X509-public-key.der delete.me
