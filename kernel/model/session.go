// SiYuan - Refactor your thinking
// Copyright (c) 2020-present, b3log.org
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package model

import (
	"image/color"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/88250/gulu"
	"github.com/gin-gonic/gin"
	"github.com/siyuan-note/logging"
	"github.com/siyuan-note/siyuan/kernel/util"
	"github.com/steambap/captcha"
)

func LogoutAuth(c *gin.Context) {
	ret := gulu.Ret.NewResult()
	defer c.JSON(http.StatusOK, ret)

	if "" == Conf.AccessAuthCode {
		ret.Code = -1
		ret.Msg = Conf.Language(86)
		ret.Data = map[string]interface{}{"closeTimeout": 5000}
		return
	}

	session := util.GetSession(c)
	util.RemoveWorkspaceSession(session)
	if err := session.Save(c); nil != err {
		logging.LogErrorf("saves session failed: " + err.Error())
		ret.Code = -1
		ret.Msg = "save session failed"
	}
}

func LoginAuth(c *gin.Context) {
	ret := gulu.Ret.NewResult()
	defer c.JSON(http.StatusOK, ret)

	arg, ok := util.JsonArg(c, ret)
	if !ok {
		return
	}

	var inputCaptcha string
	session := util.GetSession(c)
	workspaceSession := util.GetWorkspaceSession(session)
	if util.NeedCaptcha() {
		captchaArg := arg["captcha"]
		if nil == captchaArg {
			ret.Code = 1
			ret.Msg = Conf.Language(21)
			return
		}
		inputCaptcha = captchaArg.(string)
		if "" == inputCaptcha {
			ret.Code = 1
			ret.Msg = Conf.Language(21)
			return
		}

		if strings.ToLower(workspaceSession.Captcha) != strings.ToLower(inputCaptcha) {
			ret.Code = 1
			ret.Msg = Conf.Language(22)
			return
		}
	}

	authCode := arg["authCode"].(string)
	if Conf.AccessAuthCode != authCode {
		ret.Code = -1
		ret.Msg = Conf.Language(83)

		util.WrongAuthCount++
		workspaceSession.Captcha = gulu.Rand.String(7)
		if util.NeedCaptcha() {
			ret.Code = 1 // 需要渲染验证码
		}

		if err := session.Save(c); nil != err {
			logging.LogErrorf("save session failed: " + err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		return
	}

	workspaceSession.AccessAuthCode = authCode
	util.WrongAuthCount = 0
	workspaceSession.Captcha = gulu.Rand.String(7)
	if err := session.Save(c); nil != err {
		logging.LogErrorf("save session failed: " + err.Error())
		c.Status(http.StatusInternalServerError)
		return
	}
}

func GetCaptcha(c *gin.Context) {
	img, err := captcha.New(100, 26, func(options *captcha.Options) {
		options.CharPreset = "ABCDEFGHKLMNPQRSTUVWXYZ23456789"
		options.Noise = 0.5
		options.CurveNumber = 0
		options.BackgroundColor = color.White
	})
	if nil != err {
		logging.LogErrorf("generates captcha failed: " + err.Error())
		c.Status(http.StatusInternalServerError)
		return
	}

	session := util.GetSession(c)
	workspaceSession := util.GetWorkspaceSession(session)
	workspaceSession.Captcha = img.Text
	if err = session.Save(c); nil != err {
		logging.LogErrorf("save session failed: " + err.Error())
		c.Status(http.StatusInternalServerError)
		return
	}

	if err = img.WriteImage(c.Writer); nil != err {
		logging.LogErrorf("writes captcha image failed: " + err.Error())
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}

func CheckReadonly(c *gin.Context) {
	if util.ReadOnly {
		result := util.NewResult()
		result.Code = -1
		result.Msg = Conf.Language(34)
		result.Data = map[string]interface{}{"closeTimeout": 5000}
		c.JSON(http.StatusOK, result)
		c.Abort()
		return
	}
}

//限制访问很无聊，此产品应专注于本职业务，安全性相关操作由其他组件完成更为合理
func CheckAuth(c *gin.Context) {
	c.Next()
}

var timingAPIs = map[string]int{
	"/api/search/fullTextSearchBlock": 200, // Monitor the search performance and suggest solutions https://github.com/siyuan-note/siyuan/issues/7873
}

func Timing(c *gin.Context) {
	p := c.Request.URL.Path
	tip, ok := timingAPIs[p]
	if !ok {
		c.Next()
		return
	}

	timing := 15 * 1000
	if timingEnv := os.Getenv("SIYUAN_PERFORMANCE_TIMING"); "" != timingEnv {
		val, err := strconv.Atoi(timingEnv)
		if nil == err {
			timing = val
		}
	}

	now := time.Now().UnixMilli()
	c.Next()
	elapsed := int(time.Now().UnixMilli() - now)
	if timing < elapsed {
		logging.LogWarnf("[%s] elapsed [%dms]", c.Request.RequestURI, elapsed)
		util.PushMsg(Conf.Language(tip), 7000)
	}
}

func Recover(c *gin.Context) {
	defer func() {
		logging.Recover()
		c.Status(http.StatusInternalServerError)
	}()

	c.Next()
}
