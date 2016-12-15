package db

import (
	"errors"
)

type UsersInfo struct {
	UserId  string
	Token   string
	Priv    string
	PkChain string
}

///用户表操作
func (sqks *SqlDB) ReadUserInfo(userinfo map[string]interface{}) error {

	db := sqks.OpenDB()
	if db == nil {
		return errors.New("数据库连接出错,连接指针为空！")
	}
	defer db.Close()

	rows, err := db.Query("select user_id,token,priv,pkchain from t_user")
	if err != nil {
		logger.Error(err)
		return err
	}

	for rows.Next() {
		var userinfotemp UsersInfo
		err = rows.Scan(&userinfotemp.UserId, &userinfotemp.Token, &userinfotemp.Priv, &userinfotemp.PkChain)
		if err != nil {
			return err
			logger.Error(err)
		}
		userinfo[userinfotemp.UserId] = userinfotemp
	}
	return nil
}

func (sqks *SqlDB) ReadUser(userinfo *UsersInfo, userid string) error {
	db := sqks.OpenDB()
	if db == nil {
		return errors.New("数据库连接出错,连接指针为空！")
	}
	defer db.Close()

	rows := db.QueryRow("select user_id,token,priv,pkchain from t_user where user_id=?", userid)
	err := rows.Scan(&userinfo.UserId, &userinfo.Token, &userinfo.Priv, &userinfo.PkChain)
	if err != nil {
		logger.Error(err)
		return err
	}
	return nil
}

func (sqks *SqlDB) ADDUser(userinfo *UsersInfo) error {
	db := sqks.OpenDB()
	if db == nil {
		return errors.New("数据库连接出错,连接指针为空！")
	}
	defer db.Close()

	//开启事务
	tx, err := db.Begin()
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	//使用tx
	stmt, err := tx.Prepare("insert into t_user(user_id,token,priv,pkchain)values(?,?,?,?)")
	if err != nil {
		logger.Error(err.Error())
		tx.Rollback()
		return err
	}

	if result, err := stmt.Exec(userinfo.UserId, userinfo.Token, userinfo.Priv, userinfo.PkChain); err == nil {
		if id, err := result.LastInsertId(); err == nil {
			logger.Debugf("insert id : %d,err: %d", id, err)
		}
	} else {
		tx.Rollback()
		logger.Error(err.Error())
		return err
	}
	//提交事务
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		logger.Error(err)
		return err
	}
	return nil
}

func (sqks *SqlDB) UpdateUser(userinfo *UsersInfo, userid string) error {

	db := sqks.OpenDB()
	if db == nil {
		return errors.New("数据库连接出错,连接指针为空！")
	}
	defer db.Close()

	//开启事务
	tx, err := db.Begin()
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	//使用tx
	stmt, err := tx.Prepare("update t_user set user_id=?,token=?,priv=?,pkchain=? where user_id=?")
	if err != nil {
		logger.Error(err.Error())
		tx.Rollback()
		return err
	}

	if result, err := stmt.Exec(userinfo.UserId, userinfo.Token, userinfo.Priv, userinfo.PkChain); err == nil {
		if c, err := result.RowsAffected(); err == nil {
			logger.Debugf("update count : %d", c)
		}
	} else {
		logger.Error(err.Error())
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		logger.Error(err)
		return err
	}
	return nil

}

func (sqks *SqlDB) DeleteUser(userid string) error {
	db := sqks.OpenDB()
	if db == nil {
		return errors.New("数据库连接出错,连接指针为空！")
	}
	defer db.Close()

	stmt, err := db.Prepare("delete from t_user where user_id=?")
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	if result, err := stmt.Exec(userid); err == nil {
		if c, err := result.RowsAffected(); err == nil {
			logger.Debugf("remove count : %d", c)
		}
	}
	return err
}
