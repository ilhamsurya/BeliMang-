package adapter

import (
	"projectsphere/beli-mang/config"
	"strconv"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

var (
	jwtCache     *cache.Cache
	jwtCacheOnce sync.Once
)

func GetJWTCache() *cache.Cache {

	expire, _ := strconv.Atoi(config.GetString("JWT_EXPIRE"))

	jwtCacheOnce.Do(func() {
		exp := (time.Duration(expire) * time.Second) - time.Minute
		jwtCache = cache.New(exp, exp)
	})

	if jwtCache == nil {
		panic("jwt cache is not initialized")
	}
	return jwtCache
}
