// running in node: export NODE_PATH=$NODE_PATH:~/projects/ndn/ndn-clones/

// data name example
// /org/openmhealth/BwInbugZnm7dS0zjZKa3Q0PlFooURUv8A6MOnOMz4wyXqTxiIrYNn7BWjAeF/data/fitness/physical_activity/time_location/%FC%00%00%01R%5C%08N%9B
// catalog name example
// /org/openmhealth/BwInbugZnm7dS0zjZKa3Q0PlFooURUv8A6MOnOMz4wyXqTxiIrYNn7BWjAeF/data/fitness/physical_activity/time_location/catalog/%FC%00%00%01R%5C%0Br%00/%FD%01

var Face = require('ndn-js').Face;
var Name = require('ndn-js').Name;
var UnixTransport = require('ndn-js').UnixTransport;
var Exclude = require('ndn-js').Exclude;

// Data recorded this morning: z8miG6uIvHZBqdXyExbd0BIyB1CGRzQQ81T6b2xHuc8qTKnopYFri3WEzeUt

var Config = {
	hostName: "localhost",
  wsPort: 9696,
  defaultUsername: "haitao",
  defaultPrefix: "/org/openmhealth/",
  catalogPrefix: "/data/fitness/physical_activity/time_location/catalog/",
  dataPrefix: "/data/fitness/physical_activity/time_location/",
  defaultInterestLifetime: 1000,

  // not a reliable way for determining if catalog probe has finished
  catalogTimeoutThreshold: 1
}

var face = new Face({host: Config.hostName, port: Config.wsPort});
var catalogTimeoutCnt = 0;

var userCatalogs = [];
var catalogProbeFinished = false;

var catalogProbeFinishedCallback = null;

// Setting up keyChain
var identityStorage = new IndexedDbIdentityStorage();
var privateKeyStorage = new IndexedDbPrivateKeyStorage();
var policyManager = new NoVerifyPolicyManager();

var certBase64String = "";

var keyChain = new KeyChain
  (new IdentityManager(identityStorage, privateKeyStorage),
   policyManager);
keyChain.setFace(face);

var consumerIdentityName = new Name("/org/openmhealth/dvu");
var memoryContentCache = new MemoryContentCache(face);
var certificateName = undefined;

this.keyChain.createIdentityAndCertificate(consumerIdentityName, function(myCertificateName) {
  console.log("myCertificateName: " + myCertificateName.toUri());
  certificateName = myCertificateName;

  face.setCommandSigningInfo(keyChain, myCertificateName);
  memoryContentCache.registerPrefix(consumerIdentityName, onRegisterFailed, onDataNotFound);
  
  self.keyChain.getIdentityManager().identityStorage.getCertificatePromise(myCertificateName, true).then(function(certificate) {
    certBase64String = certificate.wireEncode().buf().toString('base64');
    memoryContentCache.add(certificate);
  });
}, function (error) {
  console.log("Error in createIdentityAndCertificate: " + error);
});

function onRegisterFailed(prefix) {
  console.log("Register failed for prefix: " + prefix);
}

function onDataNotFound(prefix, interest, face, interestFilterId, filter) {
  console.log("Data not found for interest: " + interest.getName().toUri());
}

var onCatalogData = function(interest, data) {
  var catalogTimestamp = data.getName().get(-2);
  var exclude = new Exclude();
  exclude.appendAny();
  // this looks for the next catalog of this user
  exclude.appendComponent(catalogTimestamp);

  var nextCatalogInterest = new Interest(interest);
  nextCatalogInterest.setExclude(exclude);
  face.expressInterest(nextCatalogInterest, onCatalogData, onCatalogTimeout);

  // this looks for the latest version of this catalog; note: this is not a reliable way to get the latest version
  var catalogVersion = data.getName().get(-1);
  var nextVersionInterest = new Interest(interest);
  nextVersionInterest.setName(data.getName().getPrefix(-1));
  // to exclude the cached received version;
  var versionExclude = new Exclude();
  versionExclude.appendAny();
  versionExclude.appendComponent(catalogVersion);
  nextVersionInterest.setExclude(versionExclude);
  
  face.expressInterest(nextVersionInterest, onCatalogVersionData, onCatalogVersionTimeout);
  catalogTimeoutCnt = 0;

  onCatalogVersionData(interest, data);
};

var onCatalogVersionData = function(interest, data) {
  console.log("Got versioned catalog: " + data.getName().toUri());

  var catalogVersion = data.getName().get(-1);
  var catalogTimestamp = data.getName().get(-2);

  var dataContent = JSON.parse(data.getContent().buf().toString('binary'));
  var username = interest.getName().get(2).toEscapedString();
  if (username in userCatalogs) {
    if (catalogTimestamp.toEscapedString() in userCatalogs[username]) {
      if (userCatalogs[username][catalogTimestamp.toEscapedString()].last_version < catalogVersion.toVersion()) {
        userCatalogs[username][catalogTimestamp.toEscapedString()] = {"last_version": catalogVersion.toVersion(), "content": dataContent};
      } else {
        console.log("Received duplicate or previous version.");
      }
    } else {
      userCatalogs[username][catalogTimestamp.toEscapedString()] = {"last_version": catalogVersion.toVersion(), "content": dataContent};
    }
  } else {
    userCatalogs[username] = [];
    userCatalogs[username][catalogTimestamp.toEscapedString()] = {"last_version": catalogVersion.toVersion(), "content": dataContent};
  }
}

var onCatalogVersionTimeout = function(interest) {
  console.log("Catalog version times out.");
}

var onCatalogTimeout = function(interest) {
  console.log("Time out for catalog interest " + interest.getName().toUri());
  catalogTimeoutCnt += 1;
  if (catalogTimeoutCnt < Config.catalogTimeoutThreshold) {
    face.expressInterest(interest, onCatalogData, onCatalogTimeout);
  } else {
    console.log("No longer looking for more catalogs.");
    catalogProbeFinished = true;
    if (catalogProbeFinishedCallback != null) {
      catalogProbeFinishedCallback(userCatalogs);
    } else {
      console.log("Catalog probe finished, callback unspecified");
    }
  }
};

// given a userPrefix, populates userCatalogs[username] with all of its catalogs
function getCatalogs(username) {
  if (username == undefined) {
    username = Config.defaultUsername;
  }
  var name = new Name(Config.defaultPrefix).append(new Name(username)).append(new Name(Config.catalogPrefix));
  var interest = new Interest(name);
  interest.setInterestLifetimeMilliseconds(Config.defaultInterestLifetime);
  // start from leftmost child
  interest.setChildSelector(0);
  interest.setMustBeFresh(true);

  console.log("Express name " + name.toUri());
  face.expressInterest(interest, onCatalogData, onCatalogTimeout);

  document.getElementById("content").innerHTML += "Fetching fitness data under name: " + username + "<br>";
};

// For unencrypted data
function getUnencryptedData(catalogs) {
  if (!catalogProbeFinished) {
    console.log("Catalog probe still in progress; may fetch older versioned data.");
  }
  for (username in catalogs) {
    var name = new Name(Config.defaultPrefix + username + Config.dataPrefix);
    for (catalog in catalogs[username]) {
      for (dataItem in catalogs[username][catalog].content) {
        var isoTimeString = Schedule.toIsoString(catalogs[username][catalog].content[dataItem] * 1000);
        var interest = new Interest(new Name(name).append("SAMPLE").append(isoTimeString));
        interest.setInterestLifetimeMilliseconds(Config.defaultInterestLifetime);
        face.expressInterest(interest, onAppData, onAppDataTimeout);
      }
    }
  }
}

// For encrypted data
function getEncryptedData(catalogs) {
  if (!catalogProbeFinished) {
    console.log("Catalog probe still in progress; may fetch older versioned data.");
  }
  for (username in catalogs) {
    var name = new Name(Config.defaultPrefix + username + Config.dataPrefix);
    for (catalog in catalogs[username]) {
      for (dataItem in catalogs[username][catalog].content) {
        var isoTimeString = Schedule.toIsoString(catalogs[username][catalog].content[dataItem] * 1000);
        var interest = new Interest(new Name(name).append("SAMPLE").append(isoTimeString));
        // TODO: user consumer.consume
      }
    }
  }
}

function requestDataAccess(username) {
  if (certBase64String == "") {
    console.log("Cert not yet generated!");
    return;
  }
  if (username == undefined) {
    username = Config.defaultUsername;
  }
  var name = new Name(Config.defaultPrefix).append(new Name(username)).append(new Name("read_access_request")).append(new Name(certificateName));
  var interest = new Interest(name);
  //interest.setInterestLifetimeMilliseconds(Config.defaultInterestLifetime);
  interest.setMustBeFresh(true);

  console.log("Express name " + name.toUri());
  face.expressInterest(interest, onCatalogData, onCatalogTimeout);
}

function onAccessRequestData(interest, data) {
  console.log("access request data received: " + data.getName().toUri());
}

function onAccessRequestTimeout(interest) {
  console.log("access request " + interest.getName().toUri() + " times out!");
}

function formatTime(unixTimestamp) {
  var a = new Date(unixTimestamp);
  var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  var year = a.getFullYear();
  var month = months[a.getMonth()];
  var date = a.getDate();
  var hour = a.getHours();
  var min = a.getMinutes();
  var sec = a.getSeconds();
  var time = date + ' ' + month + ' ' + year + ' ' + hour + ':' + min + ':' + sec ;
  return time;
}

// enumerate the current list of users in repo
function onUserData(interest, data) {
  console.log("Got user: " + data.getName().get(2).toEscapedString());
  var newInterest = new Interest(interest);
  newInterest.getExclude().appendComponent(data.getName().get(2));
  face.expressInterest(newInterest, onUserData, onUserTimeout);
  console.log("Express name " + newInterest.getName().toUri());
}

function onUserTimeout(interest) {
  console.log("User interest timeout; scan for user finishes");
}

function getUsers(prefix) {
  if (prefix == undefined) {
    prefix = Config.defaultPrefix;
  }
  var name = new Name(prefix);
  var interest = new Interest(name);
  interest.setInterestLifetimeMilliseconds(Config.defaultInterestLifetime);
  // start from leftmost child
  interest.setChildSelector(0);
  interest.setMustBeFresh(true);

  console.log("Express name " + name.toUri());
  face.expressInterest(interest, onUserData, onUserTimeout);

  document.getElementById("content").innerHTML += "Fetching users under prefix: " + prefix + "<br>";
}

var onAppData = function (interest, data) {
  console.log("Got fitness data: " + data.getName().toUri());
  var content = JSON.parse(data.getContent().buf().toString('binary'));
  console.log("Fitness payload: " + JSON.stringify(content));
  console.log("Data keyLocator keyName: " + data.getSignature().getKeyLocator().getKeyName().toUri());
  for (var i = 0; i < content.length; i++) {
    document.getElementById("content").innerHTML += formatTime(content[i].timeStamp) + "  " + JSON.stringify(content[i]) + "<br>";
  }
}

var onAppDataTimeout = function (interest) {
  console.log("App interest times out: " + interest.getName().toUri());
}

// Calling DPU
function issueDPUInterest() {
  // The interest would reach DSU, who replies if data's already generated (otherwise, call DPU to generate this data)
  var interest = new Interest("/org/openmhealth/zhehao/data/fitness/physical_activity/bout/bounding_box/SAMPLE/20150825T080000/");
}