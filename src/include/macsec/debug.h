#ifndef __MACSEC_DEBUG_H__
#define __MACSEC_DEBUG_H__

#include "lwip/opt.h"

#if defined(MACSEC) && MACSEC == 1

#include <stdio.h>

/*! \brief If MACSEC_ERROR is defined, severe configuration errors and <br>
 *         not manageable states such as running out of memory are logged. <br>
 *         It is recommended to have this feature enabled by default. */
#define MACSEC_ERROR			/**< turns on error logging */

/*! \brief If less critical errors should also be logged, this feature must
           be enabled. The produced additional output can be a supplement
           to the error messages logged under MACSEC_ERROR. */
/*#define MACSEC_DEBUG			**< turns on debug messages */

/*! \brief This feature controls informative messages. They are particularly helpful
           to have a "lightweight trace" of the program execution. */
/* #define MACSEC_MESSAGE		**< turns on informative message logging */

/*! \brief If in-depth information with details of all passed and returned
           parameters is needed, MACSEC_TRACE must be defined. Since this feature
           produces a vast amount of information, it is recommended to disable it by default. */
/* #define MACSEC_TRACE			**< turns on trace messages for macsec testing */

/*! \brief If defined, auditable events according to the IPsec RFC's are logged. */
/* #define MACSEC_AUDIT			**< turns on audit messages according RFC 2401 */

/*! \brief This feature is only used inside the test routines and prints log messages in an uniform style.  */
#define MACSEC_TEST			/**< turns on test messages for macsec testing */

/*! \brief Printing a HEX-dump of large memory buffers can be very time consuming. Only if defined, dumping of buffers is enabled. */
/* #define MACSEC_DUMP_BUFFERS	**< turns on dumping of large memory buffers (disable to speed-up) */

/*! \brief Some information is printed in tables. To avoid this time consuming operation, this feature must be disabled. */
#define MACSEC_TABLES		/**< turns on logging for any kind of tables */



/*! \brief This macro defines a standard log message size, which can be used for concatenation of log messages (sprintf(), etc) */
#define MACSEC_LOG_MESSAGE_SIZE (128)


/* @def When error logging is activated (MACSEC_ERROR), then we define a logging function for it. Otherwise nothing is printed */
#ifdef MACSEC_ERROR
	#define MACSEC_LOG_ERR(__function_name__, __code__, __message__) { \
				printf("ERR %-28s: %9d : ", __function_name__, __code__); \
				printf __message__ ;  \
				printf("\n"); \
			}
#else
	#define MACSEC_LOG_ERR(__function_name__, __code__, __message__)
#endif


/* @def When debug messages are turned on (MACSEC_DEBUG), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef MACSEC_DEBUG
	#define MACSEC_LOG_DBG(__function_name__, __code__, __message__) { \
				printf("DBG %-28s: %9d : ", __function_name__, __code__); \
				printf __message__ ;  \
				printf("\n"); \
			}
#else
	#define MACSEC_LOG_DBG(__function_name__, __code__, __message__)
#endif

/* @def When informative messages are turned on (MACSEC_MESSAGE), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef MACSEC_MESSAGE
	#define MACSEC_LOG_MSG(__function_name__, __message__) { \
				printf("MSG %-28s: ", __function_name__); \
				printf __message__ ;  \
				printf("\n"); \
			}
#else
	#define MACSEC_LOG_MSG(__function_name__, __message__)
#endif

/* @def When informative audit messages are turned on (MACSEC_AUDIT), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef MACSEC_AUDIT
	#define MACSEC_LOG_AUD(__function_name__, __code__, __message__) { \
				printf("AUD %-28s: %9d : ", __function_name__, __code__); \
				printf __message__ ;  \
				printf("\n"); \
			}
#else
	#define MACSEC_LOG_AUD(__function_name__, __code__, __message__)
#endif

/* @def When test messages are turned on (MACSEC_TEST), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef MACSEC_TEST
	#define MACSEC_LOG_TST(__function_name__, __code__, __message__) { \
				printf("TST %-28s: %9s : ", (char*)__function_name__, __code__); \
				printf __message__ ;  \
				printf("\n"); \
			}
	#define MACSEC_LOG_TST_NOMSG(__function_name__, __code__) printf("TST %-28s: %9s : ", __function_name__, __code__)
#else
	#define MACSEC_LOG_TST(__function_name__, __code__, __message__)
	#define MACSEC_LOG_TST_NOMSG(__function_name__, __code__)
#endif


/* @def When trace messages are turned on (MACSEC_TRACE), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef MACSEC_TRACE
/*
	#define MACSEC_TRACE_ENTER   1
	#define MACSEC_TRACE_RETURN -1

	extern int __macsec_trace_indication;
	extern int __macsec_trace_indication__pos;

	#define MACSEC_LOG_TRC(__action__, __function_name__, __message__) { \
				if(__action__ == (MACSEC_TRACE_ENTER | (__macsec_trace_indication < 0))) { \
					__macsec_trace_indication++; \
	                for(__macsec_trace_indication__pos = 0; __macsec_trace_indication__pos < __macsec_trace_indication; __macsec_trace_indication__pos++) {\
						printf("  "); \
					} \
					printf("ENTER  %s(", __function_name__); \
				} else { \
	                for(__macsec_trace_indication__pos = 0; __macsec_trace_indication__pos < __macsec_trace_indication; __macsec_trace_indication__pos++) {\
						printf("  "); \
					} \
					__macsec_trace_indication--; \
					printf("RETURN %s(", __function_name__); \
				} \
				printf __message__ ;\
				printf(")\n"); \
			}
	#define MACSEC_LOG_TST_NOMSG(__function_name__, __code__) printf("TST %-28s: %9s : ", __function_name__, __code__)
*/
	#define MACSEC_LOG_TRC(__action__, __function_name__, __message__)
#else
	#define MACSEC_LOG_TRC(__action__, __function_name__, __message__)
#endif

/* @def When buffer dumping is turned on (MACSEC_DUMP_BUFFERS), then we define a dump function for it. Otherwise nothing is printed. */
#ifdef MACSEC_DUMP_BUFFERS
	#define MACSEC_DUMP_BUFFER(__prefix__, __buffer__, __offset__, __length__) macsec_dump_buffer(__prefix__, __buffer__, __offset__, __length__)
#else
	#define MACSEC_DUMP_BUFFER(__prefix__, __buffer__, __offset__, __length__)
#endif

#endif /* defined(MACSEC) && MACSEC == 1 */

#endif
