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
  defaultUsername: "zhehao",
  defaultPrefix: "/org/openmhealth/",
  catalogPrefix: "/data/fitness/physical_activity/time_location/catalog/",
  dataPrefix: "/fitness/physical_activity/time_location/",
  defaultInterestLifetime: 1000,

  // not a reliable way for determining if catalog probe has finished
  catalogTimeoutThreshold: 1,
  lngOffset: 150,
  lngTimes: 4
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

var consumerIdentityName = new Name("/org/openmhealth/dvu-browser");
var memoryContentCache = new MemoryContentCache(face);
var certificateName = undefined;

// For now, hard-coded group name
var groupName = new Name("/org/openmhealth/zhehao");
indexedDB.deleteDatabase("consumer-db");
var consumerDb = new IndexedDbConsumerDb("consumer-db");
var DPUPrefix = "/ndn/edu/ucla/remap/dpu/bounding_box";
var DSULink = "/ndn/edu/ucla/remap";
var nacConsumer = new Consumer(face, keyChain, groupName, consumerIdentityName, consumerDb);

function init() {
  document.getElementById("identity").value = consumerIdentityName.toUri();
  document.getElementById("group-manager").value = groupName.toUri();
  document.getElementById("dsu-link").value = DSULink;
  document.getElementById("dpu-prefix").value = DPUPrefix;
}

this.keyChain.createIdentityAndCertificate(consumerIdentityName, function(myCertificateName) {
  console.log("myCertificateName: " + myCertificateName.toUri());
  certificateName = myCertificateName;

  face.setCommandSigningInfo(keyChain, myCertificateName);
  memoryContentCache.registerPrefix(consumerIdentityName, onRegisterFailed, onDataNotFound);
  
  keyChain.getIdentityManager().identityStorage.getCertificatePromise(myCertificateName, false).then(function(certificate) {
    certBase64String = certificate.wireEncode().buf().toString('base64');
    memoryContentCache.add(certificate);
    console.log("added my certificate to db: " + certificate.getName().toUri())
  });
  
  // Make sure we can decrypt the encrypted D-key
  getPrivateKeyAndInsertPromise(privateKeyStorage, IdentityCertificate.certificateNameToPublicKeyName(myCertificateName), consumerDb);
}, function (error) {
  console.log("Error in createIdentityAndCertificate: " + error);
});

// Hack for get private key promise...
function getPrivateKeyAndInsertPromise(privateKeyDb, keyName, consumerDb) {
  return privateKeyDb.database.privateKey.get
    (IndexedDbPrivateKeyStorage.transformName(keyName))
  .then(function(privateKeyEntry) {
    console.log(privateKeyEntry);
    console.log(keyName.toUri());
    function onComplete() {
      console.log("add key complete");
    }
    function onError(msg) {
      console.log("add key error: " + msg);
    }
    //consumer.addDecryptionKey(keyName, new Blob(privateKeyEntry.encoding), onComplete, onError);
    //return consumerDb.addKeyPromise(keyName, new Blob(privateKeyEntry.encoding));
    return Promise.resolve(consumerDb.addKeyPromise(keyName, new Blob(privateKeyEntry.encoding)));
  })
}

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
    var name = new Name(Config.defaultPrefix + username).append(new Name("SAMPLE")).append(new Name(Config.dataPrefix));
    for (catalog in catalogs[username]) {
      for (dataItem in catalogs[username][catalog].content) {
        var isoTimeString = Schedule.toIsoString(catalogs[username][catalog].content[dataItem] * 1000);
        var interest = new Interest(new Name(name).append(isoTimeString));
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
    var name = new Name(Config.defaultPrefix + username).append(new Name("SAMPLE")).append(new Name(Config.dataPrefix));
    for (catalog in catalogs[username]) {
      for (dataItem in catalogs[username][catalog].content) {
        var isoTimeString = Schedule.toIsoString(catalogs[username][catalog].content[dataItem] * 1000);
        var isoTimeString = Schedule.toIsoString(catalogs[username][catalog].content[dataItem] * 1000);
        nacConsumer.consume(new Name(name).append(isoTimeString), onConsumeComplete, onConsumeFailed);
        logString("<b>Interest</b>: " + (new Name(name).append(isoTimeString)).toUri() + " <br>");
      }
    }
  }
}

function onConsumeComplete(data, result) {
  console.log("Consumed fitness data: " + data.getName().toUri());
  var content = JSON.parse(result.buf().toString('binary'));
  console.log("Fitness payload: " + JSON.stringify(content));
  
  for (var i = 0; i < content.length; i++) {
    document.getElementById("content").innerHTML += formatTime(content[i].timeStamp) + "  " + JSON.stringify(content[i]) + "<br>";
  }

  var canvas = document.getElementById("plotCanvas");
  var ctx = canvas.getContext("2d");
  ctx.fillRect(content.lat * Config.lngTimes, (content.lng + Config.lngOffset) * Config.lngTimes, 2, 2);

  logString("<b>Data</b>: " + data.getName().toUri() + " <br>");
  logString("<b style=\"color:green\">Consume successful</b><br>");
}

function onConsumeFailed(code, message) {
  console.log("Consume failed: " + code + " : " + message);
  logString("<b>Data</b>: " + data.getName().toUri() + " <br>");
  logString("<b style=\"color:red\">Consume failed:</b>" + code + " : " + message + "<br>");
}

function requestDataAccess(username) {
  if (certBase64String == "") {
    console.log("Cert not yet generated!");
    return;
  }
  if (username == undefined) {
    username = Config.defaultUsername;
  }
  var d = new Date();
  var t = d.getTime();

  var name = new Name(Config.defaultPrefix).append(new Name(username)).append(new Name("read_access_request")).append(new Name(certificateName)).appendVersion(t);
  var interest = new Interest(name);
  //interest.setInterestLifetimeMilliseconds(Config.defaultInterestLifetime);
  interest.setMustBeFresh(true);

  console.log("Express name " + name.toUri());
  face.expressInterest(interest, onAccessRequestData, onAccessRequestTimeout);
  logString("<b>Interest</b>: " + interest.getName().toUri() + " <br>");
}

function onAccessRequestData(interest, data) {
  console.log("access request data received: " + data.getName().toUri());
  logString("<b>Data</b>: " + data.getName().toUri() + " <br>");
  logString("<b style=\"color:green\">Access granted</b><br>");
}

function onAccessRequestTimeout(interest) {
  console.log("access request " + interest.getName().toUri() + " times out!");
  logString("<b style=\"color:red\">Request timed out</b><br>");
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

function logString(str) {
  document.getElementById("log").innerHTML += str;
}

function logClear() {
  document.getElementById("log").innerHTML = "";
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

  try {
    var content = JSON.parse(data.getContent().buf().toString('binary'));
    console.log("Fitness payload: " + JSON.stringify(content));
    console.log("Data keyLocator keyName: " + data.getSignature().getKeyLocator().getKeyName().toUri());
    for (var i = 0; i < content.length; i++) {
      document.getElementById("content").innerHTML += formatTime(content[i].timeStamp) + "  " + JSON.stringify(content[i]) + "<br>";
    }

    var canvas = document.getElementById("plotCanvas");
    var ctx = canvas.getContext("2d");
    ctx.fillRect(content.lat * Config.lngTimes, (content.lng + Config.lngOffset) * Config.lngTimes, 2, 2);

    logString("<b>Interest</b>: " + interest.getName().toUri() + " <br>");
    logString("<b>Data</b>: " + data.getName().toUri() + " <br>");
    logString("<b>Consume successful</b><br>");
  } catch (e) {
    console.log(e);
    logString("<b>Interest</b>: " + interest.getName().toUri() + " <br>");
    logString("<b>Data</b>: " + data.getName().toUri() + " <br>");
    logString("<b style=\"color:red\">Consume failed</b>: " + e.toString() + "; Content " + data.getContent().buf().toString('hex') + "<br>");
  }
}

var onAppDataTimeout = function (interest) {
  console.log("App interest times out: " + interest.getName().toUri());
}

// Calling DPU
function issueDPUInterest(username) {
  if (username == undefined) {
    username = Config.defaultUsername;
  }

  var parameters = Name.fromEscapedString("/org/openmhealth/zhehao,20160320T080,/org/openmhealth/zhehao/SAMPLE/fitness/physical_activity/processed_result/bounding_box/20160320T080000");
  console.log(parameters);
  var name = new Name(DPUPrefix).append(parameters);
  // DistanceTo
  //var name = new Name(Config.defaultPrefix).append(new Name(username)).append(new Name("data/fitness/physical_activity/genericfunctions/distanceTo/(100,100)/20160320T080030"));
  var interest = new Interest(name);
  interest.setMustBeFresh(true);
  interest.setInterestLifetimeMilliseconds(10000);

  face.expressInterest(interest, onDPUData, onDPUTimeout);
  console.log("Interest expressed: " + interest.getName().toUri());
}

function onDPUData(interest, data) {
  console.log("onDPUData: " + data.getName().toUri());
  var innerData = new Data();
  innerData.wireDecode(data.getContent());

  var content = innerData.getContent().toString('binary');
  var dpuObject = JSON.parse(content);
  console.log(dpuObject);

  var canvas = document.getElementById("plotCanvas");
  var ctx = canvas.getContext("2d");
  ctx.beginPath();
  ctx.moveTo(dpuObject.minLat * Config.lngTimes, (dpuObject.minLng + Config.lngOffset) * Config.lngTimes);
  ctx.lineTo(dpuObject.minLat * Config.lngTimes, (dpuObject.maxLng + Config.lngOffset) * Config.lngTimes);

  ctx.lineTo(dpuObject.maxLat * Config.lngTimes, (dpuObject.maxLng + Config.lngOffset) * Config.lngTimes);
  ctx.lineTo(dpuObject.maxLat * Config.lngTimes, (dpuObject.minLng + Config.lngOffset) * Config.lngTimes);
  ctx.lineTo(dpuObject.minLat * Config.lngTimes, (dpuObject.minLng + Config.lngOffset) * Config.lngTimes);
  ctx.strokeStyle = '#ff0000';
  ctx.stroke();

  logString("<b>Interest</b>: " + interest.getName().toUri() + " <br>");
  logString("<b>Outer data</b>: " + data.getName().toUri() + " <br>");
  logString("<b>Inner data</b>: " + innerData.getName().toUri() + " <br>");
  logString("<b style=\"color:green\">Consume successful</b>");
}

function onDPUTimeout(interest) {
  console.log("onDPUTimeout: " + interest.getName().toUri());
  var interest = new Interest(interest);
  interest.refreshNonce();
  face.expressInterest(interest, onDPUData, onDPUTimeout);
}