certs:
	openssl genrsa -out ca-key.pem 4096
	openssl req -x509 -new -key ca-key.pem -days 1825 -out ca-cert.pem -subj '/C=US/ST=California/L=Palo Alto/O=Organization/CN=Localhost Root CA'
	openssl genrsa -out server-key.pem 4096
	openssl req -subj '/CN=*' -sha256 -new -key server-key.pem -out server.csr
	echo "subjectAltName = IP:127.0.0.1,DNS:localhost" > server-extfile.cnf
	openssl x509 -req -days 1825 -sha256 -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile server-extfile.cnf
	openssl x509 -outform der -in ca-cert.pem -out ca-cert.der
	mv ca-cert.der ca-cert.cer

.PHONY: certs