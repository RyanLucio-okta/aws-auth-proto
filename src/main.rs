use json;
use rusoto_core::signature::SignedRequest;
use rusoto_core::Region;
use rusoto_credential::AwsCredentials;
use std::error::Error;

use std::str::FromStr;

// Ref:
// from https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
// https://docs.rs/json/0.12.4/json
// https://rusoto.github.io/rusoto/rusoto_core/signature/struct.SignedRequest.html
//

const EXAMPLE_JSON_INPUT: &str = r#"
{
  "method": "POST",
  "host": "dynamodb.us-west-2.amazonaws.com",
  "relative_uri": "/",
  "service": "dynamodb",
  "region": "us-west-2",
  "headers": {
    "content-type": "application/x-amz-json-1.0",
    "host": "dynamodb.us-west-2.amazonaws.com",
    "x-amz-target": "DynamoDB_20120810.CreateTable"
        
  },
  "body": {
    "KeySchema": [
      {
        "KeyType": "HASH",
        "AttributeName": "Id"
                
      }
          
    ],
    "TableName": "TestTable",
    "AttributeDefinitions": [
      {
        "AttributeName": "Id",
        "AttributeType": "S"
                
      }
          
    ],
    "ProvisionedThroughput": {
      "WriteCapacityUnits": 5,
      "ReadCapacityUnits": 5
            
    }
      
  }
}
"#;

const EXAMPLE_JSON_OUTPUT: &str = r#"
{
    "authorization": "AWS4-HMAC-SHA256 Credential=/20200917/us-west-2/dynamodb/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target, Signature=3cfeb3c1eafd42248fa6a3911cd0e0c65f7fe327cfdddc148ece5f53a5a65d61",
    "content-length": "218",
    "content-type": "application/x-amz-json-1.0",
    "host": "dynamodb.us-west-2.amazonaws.com",
    "x-amz-content-sha256": "6dfd3a5ec3544f1e50c6d7fa3b12de088e29a938f54de32fa7170af8ae2064f7",
    "x-amz-date": "20200917T212901Z",
    "x-amz-target": "DynamoDB_20120810.CreateTable"
}
"#;

const ACCESS_KEY: &str = "";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

fn main() -> Result<(), Box<dyn Error>> {
  // ********* Get the request details for signing **********
  //
  let input = json::parse(&EXAMPLE_JSON_INPUT)?;

  let method = input["method"].as_str().unwrap();
  let service = input["service"].as_str().unwrap();
  let path = input["relative_uri"].as_str().unwrap();
  let region = input["region"].as_str().unwrap();
  let region = Region::from_str(&region).unwrap();

  let mut req = SignedRequest::new(method, service, &region, path);

  for (k, v) in input["headers"].entries() {
    req.add_header(k, v.as_str().unwrap());
  }

  // add the body to the request (this takes an Option(B))
  req.set_payload(Some(input["body"].dump()));

  // ********** Set the secret key  ************
  // The secret key will be used to compute the itermediate hashs and
  // signature
  //
  let creds = AwsCredentials::new(ACCESS_KEY, SECRET_KEY, None, None);

  // ********* Sign the request ************
  // Perform the actual v4 signature steps, e.g., build the canonical
  // request/string, calculate the signature, etc.
  //
  req.sign(&creds);

  // For this module we only need to return the headers
  //
  let mut data = json::JsonValue::new_object();

  for (k, v) in req.headers() {
    // the header values are stored as a Vec<Vec<u8>>, perhaps so that
    // each key can have multiple values?
    //
    let value = String::from_utf8(v[0].clone()).unwrap();
    data[k] = value.into();
  }

  println!("{:#}", data);

  Ok(())
}
