
The first test script to run is:

  # make -f t_openssl_suite1.makefile

That tests classic SIG algorithms (RSA, EC-DSA, DSA) that should
succeed for any openssl version (3.0.7+, 3.1, 3.2, 3.3, 3.4, 3.5).

If using openssl 3.2 and above then additional test scripts are
available for newer SIG algorithms (EC-EDWARDS, PQC-SIG):

  # make -f t_openssl_ed.makefile
  # make -f t_openssl_pqc.makefile

One additional script is available to test
TLS 1.3/1.2 (EC-DH, EC-MONTGOMERY, PQC-KEM, PQC-SIG, SIG):

  # make -f t_openssl_tls.makefile s_server3
  and
  # make -f t_openssl_tls.makefile s_client3

or
  # make -f t_openssl_tls.makefile s_server2
  and
  # make -f t_openssl_tls.makefile s_client2
