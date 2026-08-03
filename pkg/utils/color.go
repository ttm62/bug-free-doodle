package utils

import (
	"encoding/json"
	"fmt"
	"strconv"
)

type TextColor string

var (
	RedColor    TextColor = "\033[31m"
	GreenColor  TextColor = "\033[32m"
	YellowColor TextColor = "\033[33m"
	BlueColor   TextColor = "\033[34m"
	PurpleColor TextColor = "\033[35m"
	CyanColor   TextColor = "\033[36m"
	WhiteColor  TextColor = "\033[37m"
	ResetColor  TextColor = "\033[0m"

	ALL_COLORS []TextColor = []TextColor{
		RedColor,
		GreenColor,
		YellowColor,
		BlueColor,
		PurpleColor,
		CyanColor,
		WhiteColor,
		ResetColor,
	}
)

func Println(color TextColor, values ...any) {
	var res string
	var temp string

	for _, val := range values {
		switch i := val.(type) {
		case float64:
			temp = fmt.Sprintf("%.10f", i)
		case []float64:
			for index, element := range i {
				temp += fmt.Sprintf("%.10f", element)
				if index != len(i)-1 {
					temp += ", "
				}
			}
		default:
			// for type like Date, UnixTime, ...
			temp = fmt.Sprintf("%v", i)
		}

		res = res + temp + " "
	}
	fmt.Printf("%v%v%v\n", color, res, ResetColor)
}

func PtrPrintln[T any](color TextColor, values []*T, prefixs ...any) {
	var res string
	var temp string

	// add prefix
	for _, val := range prefixs {
		temp := fmt.Sprintf("%v", val)
		res = res + temp + " "
	}

	for _, ptrVal := range values {
		val := *ptrVal
		switch i := any(val).(type) {
		case float64:
			// for type like SHIB, BTC, ... price
			temp = strconv.FormatFloat(float64(i), 'f', -1, 64)
		default:
			// for type like Date, UnixTime, ...
			temp = fmt.Sprintf("%v", i)
		}

		res = res + temp + " "
	}

	fmt.Printf("%v%v%v\n", color, res, ResetColor)
}

func Pretty(data interface{}) string {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return string(b)
}
