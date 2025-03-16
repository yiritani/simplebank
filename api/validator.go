package api

import (
	"simplebank/util"

	"github.com/go-playground/validator/v10"
)

var validCurrency validator.Func = func(fieldLevel validator.FieldLevel) bool {
	currency := fieldLevel.Field().String()
	return util.IsSupportedCurrency(currency)
}
