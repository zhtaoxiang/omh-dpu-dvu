import os, time, json, base64, sys, math, getopt
from pyndn import Name, Data, Face, Interest, Exclude
from pyndn.util import Blob, MemoryContentCache
from pyndn.encrypt import Schedule, Consumer, Sqlite3ConsumerDb, EncryptedContent

from pyndn.security import KeyType, KeyChain, RsaKeyParams
from pyndn.security.certificate import IdentityCertificate
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import BasicIdentityStorage, FilePrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager

from test_consumer import DPUConsumer
from test_producer import DPUProducer

# TODO: production logic (when to trigger data production's not handled properly, in case of decryption failure)

class DPU(object):
    def __init__(self, face, identityName, groupName, catalogPrefix, rawDataPrefix, producerDbFilePath, consumerDbFilePath, encrypted = False):
        self.face = face
        # Set up the keyChain.
        identityStorage = BasicIdentityStorage()
        privateKeyStorage = FilePrivateKeyStorage()
        self.keyChain = KeyChain(
          IdentityManager(identityStorage, privateKeyStorage),
          NoVerifyPolicyManager())
        self.identityName = Name(identityName)
        self.groupName = Name(groupName)
        self.rawDataPrefix = rawDataPrefix
        self.catalogPrefix = catalogPrefix

        self.certificateName = self.keyChain.createIdentityAndCertificate(self.identityName)
        self.face.setCommandSigningInfo(self.keyChain, self.certificateName)

        # Set up the memoryContentCache
        self.memoryContentCache = MemoryContentCache(self.face)
        self.memoryContentCache.registerPrefix(self.identityName, self.onRegisterFailed, self.onDataNotFound)

        self.producerPrefix = Name(identityName)
        self.producerSuffix = Name()

        self.producer = DPUProducer(face, self.memoryContentCache, self.producerPrefix, self.producerSuffix, self.keyChain, self.certificateName, producerDbFilePath)
        
        # Put own (consumer) certificate in memoryContentCache
        consumerKeyName = IdentityCertificate.certificateNameToPublicKeyName(self.certificateName)
        consumerCertificate = identityStorage.getCertificate(self.certificateName, True)

        # TODO: request that this DPU be added as a trusted group member


        self.remainingTasks = dict()

        try:
            os.remove(consumerDbFilePath)
        except OSError:
            # no such file
            pass
        
        self.consumer = Consumer(
          face, self.keyChain, self.groupName, consumerKeyName,
          Sqlite3ConsumerDb(consumerDbFilePath))

        # TODO: Read the private key to decrypt d-key...this may or may not be ideal
        base64Content = None
        with open(privateKeyStorage.nameTransform(consumerKeyName.toUri(), ".pri")) as keyFile:
            base64Content = keyFile.read()
        der = Blob(base64.b64decode(base64Content), False)
        self.consumer.addDecryptionKey(consumerKeyName, der)

        self.memoryContentCache.add(consumerCertificate)

        self.encrypted = encrypted

        self.rawData = []

        self.catalogFetchFinished = False
        self.remainingData = 0
        return

    def onDataNotFound(self, prefix, interest, face, interestFilterId, filter):
        print "Data not found for interest: " + interest.getName().toUri()

        if interest.getName().get(-3).toEscapedString() == "bout" or interest.getName().get(-3).toEscapedString() == "genericfunctions":
            if interest.getName().toUri() in self.remainingTasks:
                # We are already trying to process this task, so we don't add it to the list of tasks
                pass
            else:
                self.remainingTasks[interest.getName().toUri()] = "in-progress";
        else:
            print "Got unexpected interest: " + interest.getName().toUri()

        # .../SAMPLE/<timestamp>
        timestamp = interest.getName().get(-1)
        catalogInterest = Interest(self.catalogPrefix)

        # Traverse catalogs in range from leftmost child
        catalogInterest.setChildSelector(0)
        catalogInterest.setMustBeFresh(True)
        catalogInterest.setInterestLifetimeMilliseconds(4000)

        exclude = Exclude()
        exclude.appendAny()
        exclude.appendComponent(timestamp)
        catalogInterest.setExclude(catalogInterest)
        self.face.expressInterest(catalogInterest, self.onCatalogData, self.onCatalogTimeout)
        print "Expressed catalog interest " + catalogInterest.getName().toUri()

        return

    def onRegisterFailed(self, prefix):
        print "Prefix registration failed"
        return

    def onCatalogData(self, interest, data):
        # Find the next catalog
        print "Received catalog data " + data.getName().toUri()

        catalogTimestamp = data.getName().get(-2)
        exclude = Exclude()
        exclude.appendAny()
        exclude.appendComponent(catalogTimestamp)

        nextCatalogInterest = Interest(interest.getName())
        nextCatalogInterest.setExclude(exclude)
        nextCatalogInterest.setChildSelector(0)
        nextCatalogInterest.setMustBeFresh(True)
        nextCatalogInterest.setInterestLifetimeMilliseconds(2000)
        self.face.expressInterest(nextCatalogInterest, self.onCatalogData, self.onCatalogTimeout)
        print "Expressed catalog interest " + nextCatalogInterest.getName().toUri()

        # We ignore the version in the catalog
        if self.encrypted:
            self.consumer.consume(contentName, self.onCatalogConsumeComplete, self.onConsumeFailed)
        else:
            self.onCatalogConsumeComplete(data, data.getContent())

    def onCatalogConsumeComplete(self, data, result):
        print "Consume complete for catalog name: " + data.getName().toUri()
        catalog = json.loads(result.toRawStr())
        
        for timestamp in catalog:
            # For encrypted data, timestamp format will have to change
            rawDataName = Name(self.rawDataPrefix).append(Schedule.toIsoString(timestamp * 1000))
            dataInterest = Interest(rawDataName)
            dataInterest.setInterestLifetimeMilliseconds(2000)
            dataInterest.setMustBeFresh(True)
            self.face.expressInterest(dataInterest, self.onRawData, self.onRawDataTimeout)
            self.remainingData += 1
        return

    # TODO: This logic for checking 'if I have everything, and should proceed with all pending tasks' is not correct for the long run 
    def onRawDataConsumeComplete(self, data, result):
        resultObject = json.loads(result.toRawStr())
        # TODO: the original data for timestamp should be an array
        self.rawData.append(resultObject)

        self.remainingData -= 1
        print "Remaing data number: " + str(self.remainingData)

        if self.remainingData == 0 and self.catalogFetchFinished:
            self.produce()

        # TODO: Unideal distanceTo production
        for item in self.remainingTasks:
            username = data.getName().get(2)
            timestamp = Name(item).get(-1).toEscapedString()
            if "distanceTo" in item and username in item and timestamp in data.getName().toUri():
                # We want this distanceTo
                destCoordinate = Name(item).get(-2).toEscapedString()
                coordinates = destCoordinate[1:-1].split(",").strip()
                x = int(coordinates[0])
                y = int(coordinates[1])
                dataObject = json.dumps({"distanceTo": math.sqrt((x - resultObject["lat"]) * (x - resultObject["lat"]) + (y - resultObject["lng"]) * (y - resultObject["lng"]))})
                
                data = Data(data)
                data.getMetaInfo().setFreshnessPeriod(40000000000)
                data.setContent(dataObject)
                self.keyChain.sign(data)

                # If the interest's still within lifetime, this will satisfy the interest
                self.memoryContentCache.add(data)

        return

    def onConsumeFailed(self, code, message):
        print "Consume error " + str(code) + ": " + message

    def onRawData(self, interest, data):
        print "Raw data received: " + data.getName().toUri()

        # TODO: Quick hack for deciding if the data is encrypted
        if "zhehao" in data.getName().toUri():
            self.consumer.consume(data.getName(), self.onRawDataConsumeComplete, self.onConsumeFailed)
        else:
            print "raw data consume complete"
            self.onRawDataConsumeComplete(data, data.getContent())

        # if self.encrypted:
        #     self.consumer.consume(data.getName(), self.onRawDataConsumeComplete, self.onConsumeFailed)
        # else:
        #     self.onRawDataConsumeComplete(data, data.getContent())

    def onCatalogTimeout(self, interest):
        print "Catalog times out: " + interest.getName().toUri()
        # TODO: 1 timeout would result in this dpu thinking that catalog fetching's done!

        self.catalogFetchFinished = True
        if self.remainingData == 0:
            self.produce()
        return

    def onRawDataTimeout(self, interest):
        print "Raw data times out: " + interest.getName().toUri()
        return

    # TODO: This logic for checking 'if I have everything, and should proceed with all pending tasks' is not correct for the long run 
    def produce(self):
        # Produce the bounding box
        print "ready to produce"
        maxLong = -3600
        minLong = 3600
        maxLat = -3600
        minLat = 3600

        if len(self.rawData) == 0:
            print "No raw data as producer input"

        for item in self.rawData:
            print item
            if item["lng"] > maxLong:
                maxLong = item["lng"]
            if item["lng"] < minLong:
                minLong = item["lng"]
            if item["lat"] > maxLat:
                maxLat = item["lat"]
            if item["lat"] < minLat:
                minLat = item["lat"]

        result = json.dumps({
            "maxlng": maxLong, 
            "minlng": minLong, 
            "maxlat": maxLat, 
            "minlat": minLat, 
            "size": len(self.rawData)
        })

        if self.encrypted:
            # TODO: replace fixed timestamp for now for produced data, createContentKey as needed
            testTime1 = Schedule.fromIsoString("20160320T080000")
            self.producer.createContentKey(testTime1)
            self.producer.produce(testTime1, result)
        else:
            # Arbitrary produced data lifetime
            data = Data(Name(self.identityName).append("20160320T080000"))
            data.getMetaInfo().setFreshnessPeriod(400000)
            data.setContent(result)

            # If the interest's still within lifetime, this will satisfy the interest
            self.memoryContentCache.add(data)
            print "Produced data with name " + data.getName().toUri()


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["name="])
    except getopt.GetoptError as err:
        print err
        usage()
        sys.exit(2)

    defaultUsername = "haitao"
    for o, a in opts:
        if o == "--name":
            defaultUsername = a

    face = Face()
    identityName = Name("/org/openmhealth/" + defaultUsername + "/SAMPLE/fitness/physical_activity/genericfunctions/bounding_box")
    groupName = Name("/org/openmhealth/" + defaultUsername + "/data/fitness")
    rawDataPrefix = Name("/org/openmhealth/" + defaultUsername + "/SAMPLE/fitness/physical_activity/time_location/")
    catalogPrefix = Name("/org/openmhealth/" + defaultUsername + "/data/fitness/physical_activity/time_location/catalog/")

    dpu = DPU(face, identityName, groupName, catalogPrefix, rawDataPrefix, "policy_config/test_producer.db", "policy_config/test_consumer.db")

    while True:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)
