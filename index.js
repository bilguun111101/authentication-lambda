const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { DynamoDB } = require("@aws-sdk/client-dynamodb");
const { marshall, unmarshall } = require("@aws-sdk/util-dynamodb");
const jwt = require('jsonwebtoken')

const db = new DynamoDB();

exports.signup = async(event) => {
  const {
    email,
    password,
    username,
    lastName,
    firstName
  } = JSON.parse(event.body);
  const userId = uuidv4();
  const hash_password = bcrypt.hashSync(password, 10);
  const user = marshall({
    userId,
    email,
    password: hash_password,
    username,
    FirstName: firstName,
    lastName
  })
  const params = {
    TableName: 'register',
    Item: user,
  }
  const response = await db.putItem(params);
  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
    },
    body: JSON.stringify({
      message: response,
    }),
  }
}

exports.signin = async(event) => {
  const {
    email,
    password,
  } = JSON.parse(event.body);
  const { Items } = await db.query({
    TableName: 'register',
    IndexName: "email-index",
    KeyConditionExpression: "email = :email",
    ExpressionAttributeValues: {
      ":email": { S: email },
    }
  })
  const clean = unmarshall(Items[0]);
  const isTrue = await bcrypt.compare(password, clean.password);
  if(!isTrue) return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
    },
    body: JSON.stringify({
      message: null,
    }),
  }
  // const accessToken = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET);
  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
    },
    body: JSON.stringify({
      data: clean,
    }),
  }
}