#include <linux/list.h>
#include "job_metadata.h"

struct job_queue {
	        struct list_head job_q; /*Queue to hold jobs */
		        struct job_metadata job_d; /* Jon specific data */
};
