### What to expect:

For example,

* Consumer names:
  * Certificate name:   /ndn/member0/KEY/ksk-1456805664/ID-CERT/%FD%00%00%01S0bVr
  * Key name:           /ndn/member0/ksk-1456805664
  * Group name:         /prefix/READ/a
  * Tries to consume:   /prefix/SAMPLE/a/b/c/20150825T080000

* Consumer actions and knowledge:
  * Publish its own certificate
  * Consume data (issue interest for data name, gets encrypted data name, asks for encrypted C-key, asks for encrypted D-key to decrypt the C-key, consults local database to decrypt the D-key)
  * Knows the group name it's in

* Producer:
  * Produced data name: /prefix/SAMPLE/a/b/c/20150825T080000/FOR/prefix/SAMPLE/a/b/c/C-KEY/20150825T080000
  * C-key name:         /prefix/SAMPLE/a/b/c/C-KEY/20150825T080000

* Producer actions and knowledge:
  * Produce and publish data
  * Try to fetch keys from all group whose name is a prefix of the producer
  * Encrypts C-key with the fetched group public key, and publishes encrypted C-key

* Group manager:
  * Group name:         /prefix/SAMPLE/a       (prefix = "/prefix", dataType = "a")
  * Group's public key: /prefix/READ/a/E-KEY/20150825T050000/20150825T100000
  * Group's encrypted D-key for a consumer: /prefix/READ/a/D-KEY/20150825T050000/20150825T100000/FOR/ndn/member0/ksk-1456805664

* Group manager actions and knowledge:
  * Adds member with the certificate name "/ndn/member0/KEY/ksk-1456805664/ID-CERT/%FD%00%00%01S0bVr"
  * Publish the group's public key, generate E-key and D-key for its member, and publish encrypted D-key for each member

### Testing:

* (For now) Install a [custom branch](https://github.com/zhehaowang/PyNDN2/tree/encryption-debug) of PyNDN2, with fixes in NBAC library functionalities (with getGroupKey and producer exclusion range change) ([sudo] python setup.py install [--user])
* Start NFD, if testing all 3 (producer, manager, consumer) on the same local machine, consider use multicast strategy for /org/openmhealth
* Run group-manager (python test\_group\_mananger.py) (the sequence of doing things, unfortunately, matters!)
* Run example producer (cd producer, python example\_data\_producer.py)
* Run consumer (python test\_consumer\_python.py for a simple consumer; or python dpu.py for a test DPU, and launch dvu/index.html for another consumer example, or trigger simple DPU computation (bounding box))

Video walkthrough (screen recording): https://www.youtube.com/watch?v=3l2w30rZqdk

For now all the names (identity, produced data names, etc); some components may not be calling "createIdentityAndCertificate" if desired identities don't exist, so please consider "ndnsec-keygen"

To access existing encrypted data on memoria.ndn.ucla.edu, use this consumer key pair and certificate: https://github.com/zhehaowang/sample-omh-dpu/tree/master/certs