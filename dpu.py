import unittest as ut
import os, time, base64, re, json, sys, getopt
from pyndn import Name, Data, Face, Interest, Link
from pyndn.util import Blob, MemoryContentCache
from pyndn.encrypt import Schedule, Consumer, Sqlite3ConsumerDb, EncryptedContent

from pyndn.security import KeyType, KeyChain, RsaKeyParams
from pyndn.security.certificate import IdentityCertificate
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import BasicIdentityStorage, FilePrivateKeyStorage, MemoryIdentityStorage, MemoryPrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager

import producer.repo_command_parameter_pb2 as repo_command_parameter_pb2
import producer.repo_command_response_pb2 as repo_command_response_pb2
from pyndn.encoding import ProtobufTlv

class TestDPU(object):
    def __init__(self, face, encryptResult, link = None):
        # Set up face
        self.face = face
        self._encryptResult = encryptResult
        self._link = link

        self.databaseFilePath = "policy_config/test_consumer_dpu.db"
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass

        self.groupName = Name("/org/openmhealth/zhehao")

        # Set up the keyChain.
        identityStorage = BasicIdentityStorage()
        privateKeyStorage = FilePrivateKeyStorage()
        self.keyChain = KeyChain(
          IdentityManager(identityStorage, privateKeyStorage),
          NoVerifyPolicyManager())
        # Authorized identity
        identityName = Name("/ndn/edu/basel/dpu")
        # Function name: the function that this DPU provides
        self._functionName = "bounding_box"
        self._identityName = identityName
        
        self.certificateName = self.keyChain.createIdentityAndCertificate(identityName)
        # TODO: if using BasicIdentityStorage and FilePrivateKeyStorage
        #   For some reason this newly generated cert is not installed by default, calling keyChain sign later would result in error
        #self.keyChain.installIdentityCertificate()
        
        self.face.setCommandSigningInfo(self.keyChain, self.certificateName)

        consumerKeyName = IdentityCertificate.certificateNameToPublicKeyName(self.certificateName)
        consumerCertificate = identityStorage.getCertificate(self.certificateName)
        self.consumer = Consumer(
          face, self.keyChain, self.groupName, identityName,
          Sqlite3ConsumerDb(self.databaseFilePath))

        # TODO: Read the private key to decrypt d-key...this may or may not be ideal
        base64Content = None
        with open(privateKeyStorage.nameTransform(consumerKeyName.toUri(), ".pri")) as keyFile:
            print privateKeyStorage.nameTransform(consumerKeyName.toUri(), ".pri")
            base64Content = keyFile.read()
            #print base64Content
        der = Blob(base64.b64decode(base64Content), False)
        self.consumer.addDecryptionKey(consumerKeyName, der)

        self.memoryContentCache = MemoryContentCache(self.face)
        self.memoryContentCache.registerPrefix(identityName, self.onRegisterFailed, self.onDataNotFound)
        self.memoryContentCache.add(consumerCertificate)

        accessRequestInterest = Interest(Name(self.groupName).append("read_access_request").append(self.certificateName).appendVersion(int(time.time())))
        self.face.expressInterest(accessRequestInterest, self.onAccessRequestData, self.onAccessRequestTimeout)
        print "Access request interest name: " + accessRequestInterest.getName().toUri()

        self._tasks = dict()

        return

    def onAccessRequestData(self, interest, data):
        print "Access request data: " + data.getName().toUri()
        return

    def onAccessRequestTimeout(self, interest):
        print "Access request times out: " + interest.getName().toUri()
        print "Assuming certificate sent and D-key generated"
        return

    def startConsuming(self, userId, basetimeString, producedDataName, dataNum, outerDataName):
        contentName = Name(userId).append(Name("/SAMPLE/fitness/physical_activity/time_location/"))
        baseZFill = 3

        for i in range(0, dataNum):
            timeString = basetimeString + str(i).zfill(baseZFill)
            timeFloat = Schedule.fromIsoString(timeString)

            self.consume(Name(contentName).append(timeString), producedDataName, outerDataName)
            print "Trying to consume: " + Name(contentName).append(timeString).toUri()

    def onDataNotFound(self, prefix, interest, face, interestFilterId, filter):
        print "Data not found for interest: " + interest.getName().toUri()
        functionComponentIdx = len(self._identityName)
        if interest.getName().get(functionComponentIdx).toEscapedString() == self._functionName:
            try:
                parameters = interest.getName().get(functionComponentIdx + 1).toEscapedString()
                pattern = re.compile('([^,]*),([^,]*),([^,]*)')
                matching = pattern.match(str(Name.fromEscapedString(parameters)))
                
                userId = matching.group(1)
                basetimeString = matching.group(2)
                producedDataName = matching.group(3)
                dataNum = 60
                self._tasks[producedDataName] = {"cap_num": dataNum, "current_num": 0, "dataset": []}
                self.startConsuming(userId, basetimeString, producedDataName, dataNum, interest.getName().toUri())
            except Exception as e:
                print "Exception in processing function arguments: " + str(e)
        else:
            print "function name mismatch: expected " + self._functionName + " ; got " + interest.getName().get(functionComponentIdx).toEscapedString()
        return

    def onRegisterFailed(self, prefix):
        print "Prefix registration failed: " + prefix.toUri()
        return

    def consume(self, contentName, producedDataName, outerDataName):
        self.consumer.consume(contentName, lambda data, result: self.onConsumeComplete(data, result, producedDataName, outerDataName), self.onConsumeFailed)

    def onConsumeComplete(self, data, result, producedDataName, outerDataName):
        print "Consume complete for data name: " + data.getName().toUri()

        if producedDataName in self._tasks:
            self._tasks[producedDataName]["current_num"] += 1
            self._tasks[producedDataName]["dataset"].append(result)
            if self._tasks[producedDataName]["current_num"] == self._tasks[producedDataName]["cap_num"]:
                maxLng = -1000
                minLng = 1000
                maxLat = -1000
                minLat = 1000
                for item in self._tasks[producedDataName]["dataset"]:
                    dataObject = json.loads(str(item))
                    if dataObject["lat"] > maxLat:
                        maxLat = dataObject["lat"]
                    if dataObject["lat"] < minLat:
                        minLat = dataObject["lat"]
                    if dataObject["lng"] > maxLng:
                        maxLng = dataObject["lng"]
                    if dataObject["lng"] < minLng:
                        minLng = dataObject["lng"]

                if not self._encryptResult:
                    innerData = Data(Name(str(producedDataName)))
                    innerData.setContent(json.dumps({"minLat": minLat, "maxLat": maxLat, "minLng": minLng, "maxLng": maxLng}))
                    #self.keyChain.sign(innerData)

                    outerData = Data(Name(str(outerDataName)))
                    outerData.setContent(innerData.wireEncode())
                    #self.keyChain.sign(outerData)

                    self.memoryContentCache.add(outerData)
                    self.initiateContentStoreInsertion("/ndn/edu/ucla/remap/ndnfit/repo", outerData)
                    print "Calculation completed, put data to repo"
                else:
                    print "Encrypt result is not implemented"

    def onConsumeFailed(self, code, message):
        print "Consume error " + str(code) + ": " + message

    def initiateContentStoreInsertion(self, repoCommandPrefix, data):
        fetchName = data.getName()
        parameter = repo_command_parameter_pb2.RepoCommandParameterMessage()
        # Add the Name.
        for i in range(fetchName.size()):
            parameter.repo_command_parameter.name.component.append(
              fetchName[i].getValue().toBytes())

        # Create the command interest.
        interest = Interest(Name(repoCommandPrefix).append("insert")
          .append(Name.Component(ProtobufTlv.encode(parameter))))
        self.face.makeCommandInterest(interest)

        self.face.expressInterest(interest, self.onRepoData, self.onRepoTimeout)

    def onRepoData(self, interest, data):
        #print "received repo data: " + interest.getName().toUri()
        return

    def onRepoTimeout(self, interest):
        #print "repo command times out: " + interest.getName().getPrefix(-1).toUri()
        return

def usage():
    print "Fill this in"
    return

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "el", ["encrypt-result", "link="])
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(2)
    
    encryptResult = False
    link = None

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-e", "--encrypt-result"):
            encryptResult = a 
        elif o in ("-l", "--link"):
            link = a
        else:
            assert False, "unhandled option"

    face = Face()
    testDPU = TestDPU(face, encryptResult, link)

    while True:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)
