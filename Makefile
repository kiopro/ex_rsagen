ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)

all:
	# compile nif
	gcc -I"$(ERLANG_PATH)" \
			-I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib \
			-lcrypto -fPIC -bundle -flat_namespace \
			-undefined suppress -m64 -arch x86_64 \
			-o priv/rsagen.so c_src/rsagen.c

clean:
	rm  -r "priv/nif.so"
