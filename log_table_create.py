import sqlite3

connection = sqlite3.connect('user.db')
cursor = connection.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS filechangehistory(
               file_id integer not null,
               file_name varchar(20) not null,
               user_login varchar(10) not null,
               last_save_time text not null
)''')

connection.commit()
connection.close()
