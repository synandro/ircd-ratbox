
/*
 * snprintf.c - just some sprintf append type functions 
 */
#include "libratbox_config.h"
#include "ratbox_lib.h"

#if (((__GNUC__ * 100) + __GNUC_MINOR__) >= 406)
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
     
/*
 * rb_vsprintf_append()
 * appends sprintf formatted string to the end of the buffer
 */

int
rb_vsprintf_append(char *str, const char *format, va_list ap)
{
	size_t x = strlen(str);
	return (vsprintf(str + x, format, ap) + (int)x);
}

/*
 * rb_sprintf_append()
 * appends sprintf formatted string to the end of the buffer
 */
int
rb_sprintf_append(char *str, const char *format, ...)
{
	int x;
	va_list ap;
	va_start(ap, format);
	x = rb_vsprintf_append(str, format, ap);
	va_end(ap);
	return (x);
}

/*
 * rb_vsnprintf_append()
 * appends sprintf formatted string to the end of the buffer but not
 * exceeding len
 */

int
rb_vsnprintf_append(char *str, size_t len, const char *format, va_list ap)
{
	size_t x;
	if(len == 0)
		return 0;
	x = strlen(str);

	if(len < x)
	{
		str[len - 1] = '\0';
		return (int)len - 1;
	}
	return (vsnprintf(str + x, len - x, format, ap) + (int)x);
}

/*
 * rb_snprintf_append()
 * appends snprintf formatted string to the end of the buffer but not
 * exceeding len
 */

int
rb_snprintf_append(char *str, size_t len, const char *format, ...)
{
	int x;
	va_list ap;
	va_start(ap, format);
	x = rb_vsnprintf_append(str, len, format, ap);
	va_end(ap);
	return (x);
}
#if (((__GNUC__ * 100) + __GNUC_MINOR__) >= 406)
#pragma GCC diagnostic pop
#endif
