/*
 * refclock_trimble - clock driver for the Trimble Palisade, Thunderbolt,
 * Acutime 2000, Acutime Gold, Resolution SMT, ACE III, Copernicus II and
 * EndRun Technologies Praecis Ct/Cf/Ce/II timing receivers
 *
 * For detailed information on this program, please refer to the
 * driver_trimble.html document accompanying the NTPsec distribution.
 *
 * Version 4.01; Febuary 18, 2025
 * refer to driver_trimble.html for change log
 *
 * This software was developed by the Software and Component Technologies
 * group of Trimble Navigation, Ltd.
 *
 * Copyright Trimble Navigation Ltd. All rights reserved.
 * Copyright the NTPsec project contributors
 * SPDX-License-Identifier: BSD-4-Clause
 */

#include "config.h"

#if defined HAVE_SYS_MODEM_H
#include <sys/modem.h>
#endif

#include <termios.h>
#include <sys/stat.h>
#include <time.h>

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include "ntpd.h"
#include "ntp_io.h"
#include "ntp_refclock.h"
#include "ntp_stdlib.h"
#include "timespecops.h"
#include "gpstolfp.h"

/*
 * GPS Definitions
 */
#define DESCRIPTION    "Trimble Palisade/Thunderbolt/Acutime/Resolution SMT" \
                       "/ACE/Copernicus GPSes" /* Long name */
#define NAME           "TRIMBLE" /* shortname */
#define PRECISION      (-20)     /* precision assumed (about 1 us) */
#define REFID          "GPS\0"   /* reference ID */
#define TRMB_MINPOLL   4         /* 16 seconds */
#define TRMB_MAXPOLL   5         /* 32 seconds */

/* minimum number of samples in the median filter to allow a poll */
#define MIN_SAMPLES    7

#define MLEN           192       /* troubleshooting message length */
#define IMSG           0         /* informational message */
#define EMSG           1         /* error message */
#define RMSG           2         /* refclock_report message */
#define MSG_MAX        RMSG      /* max message level */

/*
 * I/O Definitions
 */
#ifndef ENABLE_CLASSIC_MODE
#define	DEVICE		"/dev/trimble%d" 	/* device name and unit */
#else
#define	DEVICE		"/dev/palisade%d" 	/* device name and unit */
#endif
#define	SPEED232	B9600		  	/* uart speed (9600 baud) */

/* uart speed for Copernicus II (38400 baud) */
#define	SPEED232COP	B38400

/* parse consts */
#define RMAX 172 /* TSIP packet 0x58 can be 172 bytes */
#define DLE 0x10
#define ETX 0x03
#define MSG_TSIP 0
#define MSG_PRAECIS 1
#define SPSTAT_LEN 34 /* length of reply from Praecis SPSTAT message */

/* parse states */
#define TSIP_PARSED_EMPTY       0
#define TSIP_PARSED_FULL        1
#define TSIP_PARSED_DLE_1       2
#define TSIP_PARSED_DATA        3
#define TSIP_PARSED_DLE_2       4
#define TSIP_PARSED_ASCII       5
#define TSIP_PARSED_PARITY      6

#define mb(_X_) (up->rpt_buf[(_X_ + 1)]) /* shortcut for buffer access	*/

/*
 * Structure for build data packets for send (used by thunderbolt, ACE III and
 * resolution SMT). taken from Markus Prosch
 */
struct packettx
{
	size_t  size;
	uint8_t *data;
};

/*
 * Trimble unit control structure.
 */
struct trimble_unit {
	int                 unit; /* NTP refclock unit number */
	bool                got_pkt; /* decoded a packet this poll */
	bool                got_time; /* got a time packet this poll */
	int                 samples; /* samples in filter this poll */
	uint8_t             UTC_flags; /* UTC & leap second flag */
	uint8_t             trk_status; /* reported tracking status */
	unsigned int        rpt_status; /* TSIP Parser State */
	size_t              rpt_cnt; /* TSIP packet length so far */
	uint8_t             rpt_buf[RMAX]; /* packet assembly buffer */
	int                 type; /* Clock mode type */
	bool                use_event; /* receiver has event input */

	/* response to event input has been received */
	bool                event_reply;

	int                 MCR; /* modem control register value at startup */
	bool                parity_chk; /* enable parity checking */

	/* timestamp of last received packet */
	l_fp                p_recv_time;

	unsigned int        week; /* GPS week number */
	unsigned long       TOW; /* GPS time of week */
	int16_t             UTC_offset; /* GPS-UTC offset */
	struct calendar     date; /* calendar to avoid leap early announce */

	/* GPS week number of ntpd build date */
	unsigned int        build_week;
};

/*
 * Function prototypes
 */
static bool            trimble_start           (int, struct peer *);
static void            trimble_poll            (int, struct peer *);
static void            trimble_timer           (int, struct peer *);
static void            trimble_io              (struct recvbuf *);
static void            trimble_receive         (struct peer *, int);
static bool            TSIP_decode             (struct peer *);
static void            HW_poll                 (struct refclockproc *);
static float           getsgl                  (uint8_t *);
static double          getdbl                  (uint8_t *);
static int16_t         gets16                  (uint8_t *);
static uint16_t        getu16                  (uint8_t *);
static uint32_t        getu32                  (uint8_t *);
static void            sendcmd                 (struct packettx *, uint8_t);
static void            sendsupercmd            (struct packettx *, uint8_t,
                                                uint8_t);
static void            send_u8                 (struct packettx *, uint8_t);
static void            send_u16                (struct packettx *, uint16_t);
static ssize_t         sendetx                 (struct packettx *, int);
static void            init_thunderbolt        (int);
static void            init_resolution_smt     (int);
static NTP_PRINTF(4, 5)
       void            _tlog                   (struct peer *, bool,
                                                unsigned int, const char *,
                                                ...);

#define PAL_TSTATS 14
static const char tracking_status[PAL_TSTATS+1][16] = {
	"Doing Fixes", "Good 1SV", "Approx. 1SV", "Need Time", "Need INIT",
	"PDOP too High", "Bad 1SV", "0SV Usable", "1SV Usable", "2SV Usable",
	"3SV Usable", "No Integrity", "Diff Corr", "Overdet Clock", "Invalid"};
static const bool tracking_status_usable[PAL_TSTATS+1] = {
	true, true, false, false, false,
	false, false, false, false, false,
	false, false, false, true, false};

#define TB_DECOD_STATS 16 /* convert TB decoding status to tracking_status */
static const unsigned int tb_decod_conv[TB_DECOD_STATS+1] = {
	0, 3, 14, 5, 14, 14, 14, 14, 7, 8, 9, 10, 6, 14, 14, 14, 11};

#define TB_DISC_MODES 7
static const char tb_disc_mode[TB_DISC_MODES+1][16] = {
	"normal", "power-up", "auto holdover", "manual holdover",
	"recovery", "unknown", "disabled", "invalid"};
static const bool tb_disc_in_holdover[TB_DISC_MODES+1] = {
	false, false, true, true,
	false, false, false, false};

/*
 * Transfer vector
 */
struct refclock refclock_trimble = {
	NAME,			/* basename of driver */
	trimble_start,		/* start up driver */
	NULL,			/* shut down driver in the standard way */
	trimble_poll,		/* transmit poll message */
	NULL,			/* control - not used  */
	NULL,			/* initialize driver (not used) */
	trimble_timer		/* called at 1Hz by mainloop */
};

/* Extract the clock type from the mode setting */
#define CLK_TYPE(x) ((int)(((x)->cfg.mode) & 0x7F))

/* Supported clock types */
#define CLK_PALISADE		0	/* Trimble Palisade */
#define CLK_PRAECIS		1	/* Endrun Technologies Praecis */
#define CLK_THUNDERBOLT		2	/* Trimble Thunderbolt GPS Receiver */
#define CLK_ACUTIME   		3	/* Trimble Acutime Gold */
#define CLK_RESOLUTIONSMT	5	/* Trimble Resolution SMT Receivers */
#define CLK_ACE			6	/* Trimble ACE III */
#define CLK_COPERNICUS		7	/* Trimble Copernicus II */

/* packet 8f-ad UTC flags */
#define UTC_AVAILABLE	0x01
#define LEAP_SCHEDULED	0x10

/* shortcut check for flag1 (informational logging/printing enabled) */
#define ILOG_ON (pp->sloppyclockflag & CLK_FLAG1)

/*
 * TLOG - shortcut for _tlog that also prevents having to construct arguments
 * if the message would not be printed/logged
 */
#define TLOG(mlvl, ...) \
    do { \
	/* do nothing if flag1 and flag4 are both dim */ \
	if (!(pp->sloppyclockflag & (CLK_FLAG1|CLK_FLAG4))) { \
		break; \
	} \
	\
	/* ignore informational messages if flag 1 is not lit */ \
	if (!ILOG_ON && mlvl < EMSG) { \
		break; \
	} \
	\
	_tlog(peer, false, (mlvl), __VA_ARGS__); \
    } while (0);

/*
 * _tlog - print messages to stdout and the clockstats file.
 */
static NTP_PRINTF(4, 5) void _tlog(
	struct peer * peer,
	bool check_flags,
	unsigned int level,
	const char * fmt,
	...
	)
{
	va_list va;
	const struct refclockproc *pp = peer->procptr;
	const struct trimble_unit *up = pp->unitptr;
	const char lmsg[MSG_MAX+1][8] = {"INFO", "ERROR", "REPORT"};
	char msg[MLEN];

	if (check_flags) {
		/* do nothing if flag1 and flag4 are both dim */
		if (!(pp->sloppyclockflag & (CLK_FLAG1|CLK_FLAG4))) {
			return;
		}

		/* ignore informational messages if flag 1 is not lit */
		if (!ILOG_ON && level < EMSG) {
			return;
		}
	}

	if (level > MSG_MAX) {
		level = MSG_MAX;
	}

	va_start(va, fmt);
	IGNORE(vsnprintf(msg, MLEN, fmt, va));
	va_end(va);

	printf("TRIMBLE(%d) %s: %s\n", up->unit, lmsg[level], msg);
	mprintf_clock_stats(peer, "%s: %s", lmsg[level], msg);
}

/*
 * sendcmd - Build data packet for sending
 */
static void
sendcmd (
	struct packettx *buffer,
	uint8_t c
	)
{
	*buffer->data = DLE;
	*(buffer->data + 1) = c;
	buffer->size = 2;
}

/*
 * sendsupercmd - Build super data packet for sending
 */
static void
sendsupercmd (
	struct packettx *buffer,
	uint8_t c1,
	uint8_t c2
	)
{
	*buffer->data = DLE;
	*(buffer->data + 1) = c1;
	*(buffer->data + 2) = c2;
	buffer->size = 3;
}

static void
send_u8 (
	struct packettx *buffer,
	uint8_t b
	)
{
	if (b == DLE) {
		*(buffer->data+buffer->size++) = DLE;
	}
	*(buffer->data+buffer->size++) = b;
}

static void
send_u16 (
	struct packettx *buffer,
	uint16_t a
	)
{
	send_u8(buffer, (uint8_t)((a>>8) & 0xff));
	send_u8(buffer, (uint8_t)(a & 0xff));
}

/*
 * sendetx - Send packet or super packet to the device
 */
static ssize_t
sendetx (
	struct packettx *buffer,
	int fd
	)
{
	ssize_t result;

	*(buffer->data+buffer->size++) = DLE;
	*(buffer->data+buffer->size++) = ETX;
	result = write(fd, buffer->data, buffer->size);

	if (result != -1) {
		return result;
	} else {
		return -1;
	}
}

/*
 * init_thunderbolt - Prepares Thunderbolt receiver to be used with
 *		      NTP (also taken from Markus Prosch).
 */
static void
init_thunderbolt (
	int fd
	)
{
	struct packettx tx;
	uint8_t tx_data[10];

	tx.size = 0;
	tx.data = tx_data;

	/* set UTC time */
	sendsupercmd (&tx, 0x8E, 0xA2);
	send_u8      (&tx, 0x03);
	sendetx      (&tx, fd);

	/* activate packets 0x8F-AB and 0x8F-AC */
	sendsupercmd (&tx, 0x8E, 0xA5);
	send_u16     (&tx, 0x0005);
	sendetx      (&tx, fd);
}

/*
 * init_resolution_smt - Prepares Resolution SMT receiver to be used with
 *		         NTP (also taken from Markus Prosch).
 */
static void
init_resolution_smt (
	int fd
	)
{
	struct packettx tx;
	uint8_t tx_data[10];

	tx.size = 0;
	tx.data = tx_data;

	/* set UTC time */
	sendsupercmd (&tx, 0x8E, 0xA2);
	send_u8      (&tx, 0x03);
	sendetx      (&tx, fd);

	/* squelch PPS output unless locked to at least one satellite */
	sendsupercmd (&tx, 0x8E, 0x4E);
	send_u8      (&tx, 0x03);
	sendetx      (&tx, fd);

	/* activate packets 0x8F-AB and 0x8F-AC */
	sendsupercmd (&tx, 0x8E, 0xA5);
	send_u16     (&tx, 0x0005);
	sendetx      (&tx, fd);
}

/*
 * trimble_start - open the devices and initialize data for processing
 */
static bool
trimble_start (
	int unit,
	struct peer *peer
	)
{
	struct trimble_unit *up;
	struct refclockproc *pp;
	int fd;
	struct termios tio;
	speed_t desired_speed;
	struct calendar build_date;
	tcflag_t cflag, iflag;
	char device[20], *path;

	pp = peer->procptr;
	pp->clockname = NAME;

	/* Open serial port. */
	if (peer->cfg.path)
	    path = peer->cfg.path;
	else
	{
	    int rcode;
	    snprintf(device, sizeof(device), DEVICE, unit);

	    /* build a path */
	    rcode = snprintf(device, sizeof(device), DEVICE, unit);
	    if ( 0 > rcode ) {
	        /* failed, set to NUL */
	        device[0] = '\0';
	    }
	    path = device;
        }
	fd = refclock_open(path,
	                   peer->cfg.baud ? peer->cfg.baud :
	                   (CLK_TYPE(peer) == CLK_COPERNICUS) ?
	                   SPEED232COP : SPEED232, LDISC_RAW);
	if (0 > fd) {
	        msyslog(LOG_ERR,
		        "REFCLOCK: %s Trimble device open(%s) failed",
		        refclock_name(peer), path);
		/* coverity[leaked_handle] */
		return false;
	}

	LOGIF(CLOCKINFO, (LOG_NOTICE, "%s open at %s",
	                  refclock_name(peer), path));

	if (tcgetattr(fd, &tio) < 0) {
		msyslog(LOG_ERR, "REFCLOCK: %s tcgetattr failed: %s",
		        refclock_name(peer), strerror(errno));
		close(fd);
		return false;
	}

	/* Allocate and initialize unit structure */
	up = emalloc_zero(sizeof(*up));

	up->type = CLK_TYPE(peer);
	up->parity_chk = true;
	up->use_event = true;
	pp->disp = 1000 * S_PER_NS; /* extra ~500ns for serial port delay */

	switch (up->type) {
	    case CLK_PALISADE:
		msyslog(LOG_NOTICE, "REFCLOCK: %s Palisade mode enabled",
		        refclock_name(peer));
		break;
	    case CLK_PRAECIS:
		msyslog(LOG_NOTICE, "REFCLOCK: %s Praecis mode enabled",
		        refclock_name(peer));
		/* account for distance to tower */
		pp->disp = .00002;
		break;
	    case CLK_THUNDERBOLT:
		msyslog(LOG_NOTICE, "REFCLOCK: %s Thunderbolt mode enabled",
		        refclock_name(peer));
		up->parity_chk = false;
		up->use_event = false;
		/*
		 * packet transmission delay varies from 9ms to 32ms depending
		 * on the number of SVs the receiver is attempting to track
		 */
		pp->disp = .023;
		break;
	    case CLK_ACUTIME:
		msyslog(LOG_NOTICE, "REFCLOCK: %s Acutime Gold mode enabled",
		        refclock_name(peer));
		break;
	    case CLK_RESOLUTIONSMT:
		msyslog(LOG_NOTICE, "REFCLOCK: %s "
		        "Resolution SMT mode enabled", refclock_name(peer));
		up->use_event = false;
		break;
	    case CLK_ACE:
		msyslog(LOG_NOTICE, "REFCLOCK: %s ACE III mode enabled",
		        refclock_name(peer));
		break;
	    case CLK_COPERNICUS:
		msyslog(LOG_NOTICE, "REFCLOCK: %s Copernicus II mode enabled",
		        refclock_name(peer));
		up->use_event = false;
		up->parity_chk = false;
		break;
	    default:
	        msyslog(LOG_NOTICE, "REFCLOCK: %s mode unknown",
		        refclock_name(peer));
		close(fd);
		free(up);
		return false;
	}
	tio.c_cflag = (CS8|CLOCAL|CREAD);
	tio.c_iflag &= (tcflag_t)~ICRNL;
	if (up->parity_chk) {
		tio.c_cflag |= (PARENB|PARODD);
		tio.c_iflag &= (tcflag_t)~IGNPAR;
		tio.c_iflag |= (INPCK|PARMRK);
	}
	cflag = tio.c_cflag;
	iflag = tio.c_iflag;
	if (tcsetattr(fd, TCSANOW, &tio) == -1 || tcgetattr(fd, &tio) == -1 ||
	    tio.c_cflag != cflag || tio.c_iflag != iflag) {
		msyslog(LOG_ERR, "REFCLOCK: %s tcsetattr failed: "
		        "wanted cflag 0x%x got 0x%x, "
		        "wanted iflag 0x%x got 0x%x, return: %s",
		        refclock_name(peer), (unsigned int)cflag,
		        (unsigned int)tio.c_cflag, (unsigned int)iflag,
		        (unsigned int)tio.c_iflag, strerror(errno));
		close(fd);
		free(up);
		return false;
	}
	/*
	 * On some OS's, the calls to tcsetattr and tcgetattr above reset the
	 * baud rate to 0 as a side effect. Surprisingly, this doesn't appear
	 * to affect the operation of devices running at 9600 baud but it
	 * certainly does affect the 38400 baud Copernicus II.
	 * As a workaround, apply the baud rate once more here.
	 */
	desired_speed = peer->cfg.baud ? peer->cfg.baud :
	                (CLK_TYPE(peer) == CLK_COPERNICUS) ?
	                SPEED232COP : SPEED232;
	if (cfsetispeed(&tio, desired_speed) == -1 ||
	    cfsetospeed(&tio, desired_speed) == -1 ||
	    tcsetattr(fd, TCSANOW, &tio) == -1) {
		msyslog(LOG_ERR, "REFCLOCK: %s: "
		        "failed to set device baud rate",
		        refclock_name(peer));
		close(fd);
		free(up);
		return false;
	}

	if (up->use_event && (up->type != CLK_ACE)) {
		/*
		 * The width of the RTS pulse must be either less than 5us or
		 * greater than 600ms or the Acutime 2000 may try to switch its
		 * port A baud rate because of "Auto-DGPS". The Praecis will
		 * produce unstable timestamps (-7us instead of +-40ns offsets)
		 * when pulse width is more than a few us and less than 100us.
		 * Palisade minimum puse width is specified as 1us. To satisfy
		 * these constraints the RTS pin is idled with a positive
		 * voltage and pulsed negative.
		 */
		if (ioctl(fd, TIOCMGET, &up->MCR) < 0) {
			msyslog(LOG_ERR, "REFCLOCK: %s TIOCMGET failed: %s",
			        refclock_name(peer), strerror(errno));
			close(fd);
			free(up);
			return false;
		}
		up->MCR |= TIOCM_RTS;
		if (ioctl(fd, TIOCMSET, &up->MCR) < 0 ||
		    !(up->MCR & TIOCM_RTS)) {
			msyslog(LOG_ERR, "REFCLOCK: %s TIOCMSET failed: "
			        "MCR=0x%x, return=%s",
			        refclock_name(peer),
			        (unsigned int)up->MCR, strerror(errno));
			close(fd);
			free(up);
			return false;
		}
	}
	pp->io.clock_recv = trimble_io;
	pp->io.srcclock = peer;
	pp->io.datalen = 0;
	pp->io.fd = fd;
	if (!io_addclock(&pp->io)) {
		msyslog(LOG_ERR, "%s io_addclock failed",
		        refclock_name(peer));
		close(fd);
		pp->io.fd = -1;
		free(up);
		return false;
	}

	/* Initialize miscellaneous variables */
	pp->unitptr = up;
	pp->clockdesc = DESCRIPTION;

	peer->precision = PRECISION;
	peer->sstclktype = CTL_SST_TS_UHF;
	peer->cfg.minpoll = TRMB_MINPOLL;
	peer->cfg.maxpoll = TRMB_MAXPOLL;
	memcpy((char *)&pp->refid, REFID, REFIDLEN);

	up->unit = unit;
	up->rpt_status = TSIP_PARSED_EMPTY;
	up->rpt_cnt = 0;

	if (ntpcal_get_build_date(&build_date)) {
		caltogps(&build_date, 0, &up->build_week, NULL);
		/* timezone, UTC offset, build machine clock */
		up->build_week -= 2;
	} else {
		up->build_week = 0;
	}
	if (up->build_week < MIN_BUILD_GPSWEEK ||
	    up->build_week > MAX_BUILD_GPSWEEK) {
		msyslog(LOG_ERR,
		        "REFCLOCK: %s ntpcal_get_build_date() failed: %u",
		        refclock_name(peer), up->build_week);
		close(fd);
		pp->io.fd = -1;
		free(up);
		return false;
	}

	if (up->type == CLK_THUNDERBOLT) {
		init_thunderbolt(fd);
	}

	if (up->type == CLK_RESOLUTIONSMT) {
		init_resolution_smt(fd);
	}

	return true;
}

/*
 * TSIP_decode - decode the TSIP data packets
 */
static bool
TSIP_decode (
	struct peer *peer
	)
{
	uint8_t id;
	struct trimble_unit *up;
	struct refclockproc *pp;

	pp = peer->procptr;
	up = pp->unitptr;
	id = up->rpt_buf[0];

	if (id == 0x8f) {
		uint16_t event;
		/* Superpackets */
		event = getu16(&mb(1));
		if ((up->type != CLK_THUNDERBOLT) &&
		    (up->type != CLK_RESOLUTIONSMT) && !event) {
			/* ignore auto-report */
			return false;
		}
		switch (mb(0) & 0xff) {
		    case 0x0B:
		    {
			/*
			 * comprehensive time packet: sent after 8f-ad from
			 * Palisade and Acutime
			 */
			int32_t secint;
			double secs, secfrac;
			int trk_ct = 0;

			if (up->rpt_cnt != 74) {
				TLOG(RMSG,
				     "decode 8f-0b: packet length is not 74 "
				     "(%zu)", up->rpt_cnt);
				refclock_report(peer, CEVNT_BADREPLY);
				return false;
			}
			up->got_time = true;

			secs = getdbl(&mb(3));
			secint = (int32_t) secs;
			secfrac = secs - secint; /* 0.0 <= secfrac < 1.0 */
			pp->nsec = (long) (secfrac * NS_PER_S);

			secint %= SECSPERDAY;    /* Only care about today */
			up->date.hour = (uint8_t)(secint / SECSPERHR);
			secint %= SECSPERHR;
			up->date.minute = (uint8_t)(secint / 60);
			secint %= 60;
			up->date.second = (uint8_t)(secint % 60);
			up->date.monthday = mb(11);
			up->date.month = mb(12);
			up->date.year = getu16(&mb(13));
			up->date.yearday = 0;
			caltogps(&up->date, up->UTC_offset, &up->week,
			         &up->TOW);
			gpsweekadj(&up->week, up->build_week);
			gpstocal(up->week, up->TOW, up->UTC_offset,
			         &up->date);

			if (ILOG_ON) {
				for (int st = 66; st <= 73; st++) {
					if ((signed char)mb(st) > 0) {
						trk_ct++;
					}
				}
			}

			up->UTC_offset = gets16(&mb(16));
			TLOG(IMSG, "decode 8f-0b: #%05d %02d:%02d:%02d"
			     ".%09ld %02d/%02d/%04d UTC %d  tracking %02d SVs"
			     "  tracking status: %s",
			     event, up->date.hour, up->date.minute,
			     up->date.second, pp->nsec, up->date.month,
			     up->date.monthday, up->date.year,
			     up->UTC_offset, trk_ct,
			     tracking_status[up->trk_status]);

			if (!tracking_status_usable[up->trk_status]) {
				TLOG(EMSG, "decode 8f-0b: "
				     "unusable tracking status: %s",
				     tracking_status[up->trk_status]);
				return false;
			}

			if (!(up->UTC_flags & UTC_AVAILABLE) ||
			    (up->UTC_offset == 0)) {
				pp->leap = LEAP_NOTINSYNC;
				TLOG(EMSG, "decode 8f-0b: "
				     "UTC data not available");
				return false;
			}

			if ((up->UTC_flags & LEAP_SCHEDULED) &&
			    /* Avoid early announce: https://bugs.ntp.org/2773 */
			    (6 == up->date.month || 12 == up->date.month))
				pp->leap = LEAP_ADDSECOND;
			else
				pp->leap = LEAP_NOWARNING;

			/* don't reuse UTC flags or tracking status */
			up->UTC_flags = 0;
			up->trk_status = PAL_TSTATS;
			return true;
			break;
		    }
		    case 0xAD:
		    {
			/*
			 * primary UTC time packet: first packet sent after
			 * PPS from Palisade, Acutime, and Praecis
			 */
			if (up->rpt_cnt != 22) {
				TLOG(RMSG,
				     "decode 8f-ad: packet length is not 22 "
				     "(%zu)", up->rpt_cnt);
				refclock_report(peer, CEVNT_BADREPLY);
				return false;
			}

			/* flags checked in 8f-0b for Palisade and Acutime */
			up->trk_status = mb(18);
			if (up->trk_status > PAL_TSTATS) {
				up->trk_status = PAL_TSTATS;
			}
			up->UTC_flags = mb(19);

			pp->nsec = (long) (getdbl(&mb(3)) * NS_PER_S);
			up->date.year = getu16(&mb(16));
			up->date.hour = mb(11);
			up->date.minute = mb(12);
			up->date.second = mb(13);
			up->date.month = mb(15);
			up->date.monthday = mb(14);
			caltogps(&up->date, 0, &up->week, &up->TOW);
			gpsweekadj(&up->week, up->build_week);
			gpstocal(up->week, up->TOW, 0, &up->date);

			TLOG(IMSG, "decode 8f-ad: #%05d %02d:%02d:%02d"
			     ".%09ld %02d/%02d/%04d leap %d  UTC 0x%02x  "
			     "tracking status: %s",
			     event, up->date.hour, up->date.minute,
			     up->date.second, pp->nsec, up->date.month,
			     up->date.monthday, up->date.year,
			     pp->leap, up->UTC_flags,
			     tracking_status[up->trk_status]);

			/* get timecode from 8f-0b except with Praecis */
			if (up->type != CLK_PRAECIS)
				return false;

			if (!tracking_status_usable[up->trk_status]) {
				TLOG(EMSG, "decode 8f-ad: "
				     "unusable tracking status: %s",
				     tracking_status[up->trk_status]);
				return false;
			}
			if (!(up->UTC_flags & UTC_AVAILABLE)) {
				pp->leap = LEAP_NOTINSYNC;
				TLOG(EMSG, "decode 8f-ad: "
				     "UTC data not available");
				return false;
			}

			if ((up->UTC_flags & LEAP_SCHEDULED) &&
			    /* Avoid early announce: https://bugs.ntp.org/2773 */
			    (6 == up->date.month || 12 == up->date.month))
				pp->leap = LEAP_ADDSECOND;
			else
				pp->leap = LEAP_NOWARNING;

			return true;
			break;
		    }
		    case 0xAC:
		    {
			/*
			 * supplemental timing packet: sent after 8f-ab from
			 * Thunderbolt and Resolution SMT
			 */
			uint8_t decod_stat, disc_mode;
			uint16_t m_alarms;
			uint32_t holdover_time;

			if (up->rpt_cnt != 68) {
				TLOG(RMSG,
				     "decode 8f-ac: packet length is not 68 "
				     "(%zu)", up->rpt_cnt);
				refclock_report(peer, CEVNT_BADREPLY);
				return false;
			}
			up->got_time = true;

			decod_stat = mb(12);
			if (decod_stat > TB_DECOD_STATS) {
				decod_stat = TB_DECOD_STATS;
			}
			disc_mode = mb(2);
			if (disc_mode > TB_DISC_MODES) {
				disc_mode = TB_DISC_MODES;
			}

			m_alarms = getu16(&mb(10));

			holdover_time = getu32(&mb(4));

			gpsweekadj(&up->week, up->build_week);
			gpstocal(up->week, up->TOW, up->UTC_offset,
			         &up->date);

			TLOG(IMSG, "decode 8f-ac: TOW %lu week %u "
			     "adj.t: %02d:%02d:%02d.0 %02d/%02d/%04d  "
			     "leap=%d  decod.stat=%s  disc.mode=%s",
			     up->TOW, up->week,
			     up->date.hour, up->date.minute, up->date.second,
			     up->date.month, up->date.monthday, up->date.year,
			     pp->leap,
			     tracking_status[tb_decod_conv[decod_stat]],
			     tb_disc_mode[disc_mode]);

			if (!tracking_status_usable[
			    tb_decod_conv[decod_stat]])	{
				if (pp->fudgetime2 < 0.5) {
					/* holdover not enabled */
					TLOG(EMSG, "decode 8f-ac: "
					     "decod.stat of '%s' is unusable",
					     tracking_status[
					       tb_decod_conv[decod_stat]]);
					return false;
				} else if (tb_disc_in_holdover[disc_mode] &&
				          holdover_time > pp->fudgetime2) {
					TLOG(EMSG, "decode 8f-ac: "
					     "unit in holdover (disc.mode=%s)"
					     " with decod.stat of '%s' but "
					     "holdover time of %lus "
					     "exceeds time2(%.fs)",
					     tb_disc_mode[disc_mode],
					     tracking_status[
					       tb_decod_conv[decod_stat]],
					     (unsigned long)holdover_time,
					     pp->fudgetime2);
					return false;
				} else if (!tb_disc_in_holdover[disc_mode]) {
					TLOG(EMSG, "decode 8f-ac: "
					     "not in holdover (disc.mode=%s) "
					     "and decod.stat of '%s'"
					     "is unusable",
					     tb_disc_mode[disc_mode],
					     tracking_status[
					       tb_decod_conv[decod_stat]]);
					return false;
				}
			}

			if (up->UTC_flags != UTC_AVAILABLE)
				return false;

			if (m_alarms & 0x200) {
				TLOG(EMSG, "decode 8f-ac: "
				     "'position questionable' flag is set, "
				     "you must "
				     "update the unit's stored position.");
				return false;
			}

			if ((m_alarms & 0x80) &&
			/* Avoid early announce: https://bugs.ntp.org/2773 */
			    (6 == up->date.month || 12 == up->date.month) )
				pp->leap = LEAP_ADDSECOND;  /* we ASSUME addsecond */
			else
				pp->leap = LEAP_NOWARNING;

			return true;
			break;
		    }
		    case 0xAB:
		    {
			/*
			 * primary timing packet: first packet sent after PPS
			 * from Thunderbolt and Resolution SMT
			 */
			uint8_t timing_flags;

			if (up->rpt_cnt != 17) {
				TLOG(RMSG,
				     "decode 8f-ab: packet length is not 17 "
				     "(%zu)", up->rpt_cnt);
				refclock_report(peer, CEVNT_BADREPLY);
				return 0;
			}
			timing_flags = mb(9);
			up->UTC_flags = 0;
			up->UTC_offset = gets16(&mb(7));
			up->TOW = getu32(&mb(1));
			up->week = getu16(&mb(5));

			TLOG(IMSG, "decode 8f-ab: TOW %lu week %u "
			     "timing flags:0x%02X = "
			     "tcode aligned to %s, PPS aligned to %s, "
			     "time is %sset, UTC is %savail., "
			     "tsrc is %s",
			     up->TOW, up->week, timing_flags,
			     (timing_flags&0x08)?"GPS(UTC not avail.)":
			       timing_flags&0x01?"UTC":"GPS(misconfigured)",
			     (timing_flags&0x08)?"GPS(UTC not avail.)":
			       timing_flags&0x02?"UTC":"GPS(misconfigured)",
			     timing_flags&0x04?"NOT ":"",
			     timing_flags&0x08?"NOT ":"",
			     timing_flags&0x10?"test-mode(misconfigured)":
			       "sat.");

			if (timing_flags & 0x04 || timing_flags & 0x08 ||
			    up->UTC_offset == 0) {
				TLOG(EMSG, "decode 8f-ab: time not set or "
				     "UTC offset unavailable");
				return false;
			}
			/*
			 * configuration is sent only at ntpd startup. if unit
			 * loses power it will revert to the factory default
			 * time alignment (GPS)
			 */
			if (!(timing_flags & 0x01) ||
			    !(timing_flags & 0x02) ||
			    (timing_flags & 0x10)) {
				TLOG(EMSG, "decode 8f-ab: "
				     "timing_flags not UTC time, "
				     "unit is misconfigured (0x%02X)",
				     timing_flags);
				pp->leap = LEAP_NOTINSYNC;
				refclock_report(peer, CEVNT_BADTIME);
				return false;
			}

			pp->lastrec = up->p_recv_time;
			pp->nsec = 0;
			up->UTC_flags = UTC_AVAILABLE; /* flag for 8f-ac */
			return false;
			break;
		    }
		    default:
			break;
		} /* switch */
	} else if (id == 0x41) {
		/*
		 * GPS time packet from ACE III or Copernicus II receiver.
		 * The ACE III issues these in response to a HW poll.
		 * The Copernicus II receiver issues these by default once a
		 * second.
		 */
		double secfrac;
		float TOWfloat;
		uint32_t lastrec_frac;

		if ((up->type != CLK_ACE) && (up->type != CLK_COPERNICUS))
			return false;

		if (up->rpt_cnt != 10) {
			TLOG(RMSG,
			     "decode 0x41: packet length is not 10 (%zu)",
			     up->rpt_cnt);
			refclock_report(peer, CEVNT_BADREPLY);
			return false;
		}

		/*
		 * A negative value of TOW indicates the receiver has not
		 * established the time. This can occur even if UTC_offset is
		 * correct.
		 */
		TOWfloat = getsgl(&mb(0));
		up->got_time = (TOWfloat >= 0.f);

		up->TOW  = (unsigned long)TOWfloat;
		up->week = getu16(&mb(4));
		up->UTC_offset = (int16_t)getsgl(&mb(6));

		gpsweekadj(&up->week, up->build_week);
		gpstocal(up->week, up->TOW, up->UTC_offset, &up->date);

		TLOG(IMSG, "decode 0x41: TOWfloat %.0f got_time: %s "
		     "TOW %lu  week %u  UTC %d "
		     "adj.t: %02d:%02d:%02d.0 %02d/%02d/%04d",
		     TOWfloat, up->got_time?"yes":"no",
		     up->TOW, up->week, up->UTC_offset,
		     up->date.hour, up->date.minute, up->date.second,
		     up->date.month, up->date.monthday, up->date.year);

		if (!up->got_time) {
			TLOG(EMSG, "decode 0x41: TOWfloat negative, "
			     "time is invalid");
			return false;
		}
		if (up->UTC_offset == 0) {
			TLOG(EMSG, "decode 0x41: UTC is zero, "
			     "data not available");
			return false;
		}

		/*
		 * The HW_poll occurs at 1Hz but with random phase w.r.t the
		 * system clock. If we are using polling, cancel out the
		 * random phase offset by setting pp->nsec to the fractional
		 * part of lastrec.
		 */
		if (up->use_event) {
			lastrec_frac = lfpfrac(pp->lastrec);
			secfrac = (double)lastrec_frac / FRAC;
			pp->nsec = (long) (secfrac * NS_PER_S);
		} else {
			pp->lastrec = up->p_recv_time;
			pp->nsec = 0;
		}

		return true;
	}

	return false;
}

/*
 * trimble_receive - receive data from the serial interface
 */
static void
trimble_receive (
	struct peer * peer,
	int type
	)
{
	struct trimble_unit *up;
	struct refclockproc *pp;

	/* Initialize pointers and read the timecode and timestamp. */
	pp = peer->procptr;
	up = pp->unitptr;

	/*
	 * Wait for fudge flags to initialize. Also, startup may have caused
	 * a spurious edge, so wait for first HW_poll()
	 */
	if (pp->polls < 1)
		return;

	up->got_pkt = true;
	if (MSG_TSIP == type) {
		if (!TSIP_decode(peer))
			return;
	} else {
		if (SPSTAT_LEN == up->rpt_cnt &&
		    up->rpt_buf[up->rpt_cnt - 1] == '\r') {
			up->rpt_buf[up->rpt_cnt - 1] = '\0';
			record_clock_stats(peer, (char *) up->rpt_buf);
		}
		return;
	}

	/* add sample to filter */
	/*
         * The ACE III receiver periodically outputs 0x41 packets by itself,
         * i.e. in addition to those output in response to a poll command.
	 * When this happens, two 0x41 packets with the same contents will be
	 * received back to back.  Only process the first of these.
	 */
	if (!((up->type == CLK_ACE) && up->event_reply)) {
		pp->lastref = pp->lastrec;
		pp->year = (int)up->date.year;
		pp->yday = (int)up->date.yearday;
		pp->hour = up->date.hour;
		pp->minute = up->date.minute;
		pp->second = up->date.second;
		TLOG(IMSG, "trimble_receive: %4d %03d %02d:%02d:%02d.%09ld",
		     pp->year, pp->yday, pp->hour, pp->minute,
		     pp->second, pp->nsec);
		if (!refclock_process(pp)) {
			TLOG(RMSG, "trimble_receive: "
			     "refclock_process failed!");
			refclock_report(peer, CEVNT_BADTIME);
			return;
		}
		up->samples++;
		up->event_reply = true;
	}
}

/*
 * trimble_poll - called by the transmit procedure
 */
static void
trimble_poll (
	int unit,
	struct peer *peer
	)
{
	struct trimble_unit *up;
	struct refclockproc *pp;
	int cl;
	bool err;

	UNUSED_ARG(unit);

	pp = peer->procptr;
	up = pp->unitptr;

	/* samples are not taken until second poll */
	if (++pp->polls < 2)
		return;

	/* check status for the previous poll interval */
	err = (up->samples < MIN_SAMPLES);
	if (err) {
		refclock_report(peer, CEVNT_TIMEOUT);
		if (!up->got_pkt) {
			TLOG(EMSG, "trimble_poll: no packets found");
		} else if (!up->got_time) {
			TLOG(EMSG, "trimble_poll: "
			     "packet(s) found but none were usable. "
			     "Verify unit isn't connected to Port B and "
			     "flag3 is correct for Palisade/Acutime");
		} else {
			TLOG(EMSG, "trimble_poll: not enough samples "
			     "(%d, min %d), skipping poll",
			     up->samples, MIN_SAMPLES);
			pp->codeproc = pp->coderecv; /* reset filter */
		}
	}
	up->got_time = false;
	up->got_pkt = false;
	up->samples = 0;
	if (err)
		return;

	/* ask Praecis for its signal status */
	if(up->type == CLK_PRAECIS) {
		if(write(peer->procptr->io.fd,"SPSTAT\r\n",8) < 0)
			msyslog(LOG_ERR, "REFCLOCK: %s write: %s:",
			        refclock_name(peer), strerror(errno));
	}

	/* record clockstats */
	cl = snprintf(pp->a_lastcode, sizeof(pp->a_lastcode),
	              "%4d %03d %02d:%02d:%02d.%09ld",
	              pp->year, pp->yday, pp->hour,
	              pp->minute, pp->second, pp->nsec);
	pp->lencode = (cl < (int)sizeof(pp->a_lastcode)) ? cl : 0;
	record_clock_stats(peer, pp->a_lastcode);

	TLOG(IMSG, "trimble_poll: %s", prettydate(pp->lastrec));

	if (pp->hour == 0 && up->week > up->build_week + 1000) {
		msyslog(LOG_WARNING, "REFCLOCK: %s current GPS week number "
		        "(%u) is more than 1000 weeks past ntpd's build date "
		        "(%u), please update",
		        refclock_name(peer), up->week, up->build_week);
	}
	/* process samples in filter */
	refclock_receive(peer);
}

/*
 * trimble_io - create TSIP packets or ASCII strings from serial data stream
 */
static void
trimble_io (
	struct recvbuf *rbufp
	)
{
	struct trimble_unit *up;
	struct refclockproc *pp;
	struct peer *peer;

	uint8_t * c, * d;

	peer = rbufp->recv_peer;
	pp = peer->procptr;
	up = pp->unitptr;

	c = rbufp->recv_buffer;
	d = c + rbufp->recv_length;

	while (c != d) {
		switch (up->rpt_status) {
		    case TSIP_PARSED_DLE_1:
			switch (*c)
			{
			    case 0:
			    case DLE:
			    case ETX:
				up->rpt_status = TSIP_PARSED_EMPTY;
				break;

			    default:
				up->rpt_status = TSIP_PARSED_DATA;
				/* save packet ID */
				up->rpt_buf[0] = *c;
				/* save packet receive time */
				up->p_recv_time = rbufp->recv_time;
				break;
			}
			break;

		    case TSIP_PARSED_DATA:
			if (*c == DLE) {
				up->rpt_status = TSIP_PARSED_DLE_2;
			} else if (up->parity_chk && *c == 0xff)
				up->rpt_status = TSIP_PARSED_PARITY;
			else
				mb(up->rpt_cnt++) = *c;
			break;

		    case TSIP_PARSED_PARITY:
			if (*c == 0xff) {
				up->rpt_status = TSIP_PARSED_DATA;
				mb(up->rpt_cnt++) = *c;
			} else {
				msyslog(LOG_ERR, "REFCLOCK: %s: "
				        "detected serial parity error "
				        "or receive buffer overflow",
					refclock_name(peer));
				up->rpt_status = TSIP_PARSED_EMPTY;
			}
			break;

		    case TSIP_PARSED_DLE_2:
			if (*c == DLE) {
				up->rpt_status = TSIP_PARSED_DATA;
				mb(up->rpt_cnt++) = *c;
			} else if (*c == ETX) {
				up->rpt_status = TSIP_PARSED_FULL;
				trimble_receive(peer, MSG_TSIP);
			} else {
				/* error: start new report packet */
				up->rpt_status = TSIP_PARSED_DLE_1;
				up->rpt_buf[0] = *c;
			}
			break;

		    case TSIP_PARSED_ASCII:
			if (*c == '\n') {
				mb(up->rpt_cnt++) = *c;
				up->rpt_status = TSIP_PARSED_FULL;
				trimble_receive(peer, MSG_PRAECIS);
			} else if (up->parity_chk && *c == 0xff) {
				up->rpt_status = TSIP_PARSED_PARITY;
			} else {
				mb(up->rpt_cnt++) = *c;
			}
			break;

		    case TSIP_PARSED_FULL:
		    case TSIP_PARSED_EMPTY:
		    default:
			up->rpt_cnt = 0;
			if (*c == DLE) {
				up->rpt_status = TSIP_PARSED_DLE_1;
			} else if (up->type == CLK_PRAECIS &&
			           NULL != strchr("6L789ADTP", (char)*c)) {
				/* Praecis command reply */
				up->rpt_buf[0] = *c;
				up->rpt_status = TSIP_PARSED_ASCII;
			} else {
 				up->rpt_status = TSIP_PARSED_EMPTY;
			}
			break;
		}
		c++;
		if (up->rpt_cnt > RMAX - 2) {/* additional byte for ID */
			up->rpt_status = TSIP_PARSED_EMPTY;
			TLOG(IMSG, "trimble_io: "
			     "oversize serial message (%zuB) 0x%02x "
			     "discarded", up->rpt_cnt, up->rpt_buf[0]);
		}
	} /* while chars in buffer */
}

/*
 * trimble_timer - trigger an event at 1Hz
 */
static void
trimble_timer(
	int unit,
	struct peer * peer
	)
{
	struct trimble_unit *up;
	struct refclockproc *pp;

	UNUSED_ARG(unit);

	pp = peer->procptr;
	up = pp->unitptr;

	if (up->use_event)
		HW_poll(pp);
}

/*
 * HW_poll - trigger the event input
 */
static void
HW_poll (
	struct refclockproc * pp
	)
{
	struct trimble_unit *up;
	static const struct timespec ts = {0, 13 * NS_PER_MS};

	up = pp->unitptr;

	struct packettx tx;
	uint8_t tx_data[10];
	if (up->type == CLK_ACE) {
		/* Poll ACE III by sending a 0x21 command */
		tx.size = 0;
		tx.data = tx_data;
		sendcmd (&tx, 0x21);
		sendetx (&tx, pp->io.fd);
	} else {
		/* Edge trigger */
		if (pp->sloppyclockflag & CLK_FLAG3) {
			IGNORE(write (pp->io.fd, "", 1));
		} else {
			/* set RTS low from high idle state */
			up->MCR &= ~TIOCM_RTS;
			IGNORE(ioctl(pp->io.fd, TIOCMSET, &up->MCR));

			/*
			 * The Acutime 2000 will occasionally transmit with
			 * parity errors if the low state is held for less
			 * than 1ms, and the Praecis will produce unstable
			 * timestamps if the low state is held for less than
			 * 12ms.
			 */
			nanosleep(&ts, NULL);

			up->MCR |= TIOCM_RTS;  /* make edge / restore idle */
			IGNORE(ioctl(pp->io.fd, TIOCMSET, &up->MCR));
		}
	}
	up->event_reply = 0;

	/* get timestamp after triggering since RAND_bytes is slow */
	get_systime(&pp->lastrec);
}

/*
 * getsgl - copy/swap a big-endian Trimble single into a host float
 */
static float
getsgl (
	uint8_t *bp
	)
{
#ifdef WORDS_BIGENDIAN
	float out;

	memcpy(&out, bp, sizeof(out));
	return out;
#else
	union {
		uint8_t ch[4];
		uint32_t u32;
	} ui;

	union {
		float out;
		uint32_t u32;
	} uo;

	memcpy(ui.ch, bp, sizeof(ui.ch));
	uo.u32 = ntohl(ui.u32);

	return uo.out;
#endif
}

/*
 * getdbl - copy/swap a big-endian Trimble double into a host double
 */
static double
getdbl (
	uint8_t *bp
	)
{
#ifdef WORDS_BIGENDIAN
	double out;

	memcpy(&out, bp, sizeof(out));
	return out;
#else
	union {
		uint8_t ch[8];
		uint32_t u32[2];
	} ui;

	union {
		double out;
		uint32_t u32[2];
	} uo;

	memcpy(ui.ch, bp, sizeof(ui.ch));
	/* least-significant 32 bits of double from swapped bp[4] to bp[7] */
	uo.u32[0] = ntohl(ui.u32[1]);
	/* most-significant 32 bits from swapped bp[0] to bp[3] */
	uo.u32[1] = ntohl(ui.u32[0]);

	return uo.out;
#endif
}

/*
 * gets16 - copy/swap a big-endian Trimble SINT16 into a host int16_t
 */
static int16_t
gets16 (
	uint8_t *bp
	)
{
	uint16_t us;

	memcpy(&us, bp, sizeof(us));
	return (int16_t)ntohs(us);
}

/*
 * getu16 - copy/swap a big-endian Trimble UINT16 into a host uint16_t
 */
static uint16_t
getu16 (
	uint8_t *bp
	)
{
	uint16_t us;

	memcpy(&us, bp, sizeof(us));
	return ntohs(us);
}

/*
 * getu32 -copy/swap a big-endian Trimble UINT32 into a host uint32_t
 */
static uint32_t
getu32(
	uint8_t *bp
	)
{
	uint32_t u32;

	memcpy(&u32, bp, sizeof(u32));
	return ntohl(u32);
}
