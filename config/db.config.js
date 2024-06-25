const mySQL =require('mysql');

const connectionString = {
    connectionLimit : 100,
    host            : 'localhost',
    user            :'root',
    password        :'root123',
    database        :'nodejs_flutter',
    debug           :false,
    port            :3306,

};

const db =mySQL.createPool(connectionString);
module.exports = {
    db,
    
};