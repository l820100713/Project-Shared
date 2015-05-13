//
//  lists.c
//
//
//  Created by Benjamin Sinclair on 4/05/2015.
//
//

#include "directors.h"

int add_entry(INFO **info, INFO *info_entry, int *info_count)
{
    info = info + (*info_count);
    (*info) = info_entry;
    info = info - (*info_count);
    *info_count = *info_count + 1;
    return 0;
}

char *check_match(INFO **info, INFO *collector, int *info_count)
{
    for(int i = 0; i < (*info_count); i ++){
        if(collector->service_type == (*info)->service_type) {
            printf("Found match of service type %c\n",(*info)->service_type);
            return (*info)->sock_str;
        }
        info++;
    }
    info = info - (*info_count);
    return NULL;
}

int remove_entry(INFO **info, char *sock_str, int *info_count)
{
    int found_index = 0;
    for(int i = 0; i < (*info_count); i ++){
        if(strcmp(sock_str, (*info)->sock_str) == 0) {
            free((*info));
            found_index = i;
            break;
        }
        info++;
    }
    if(found_index > 0) {
        for(int i = found_index; i < (*info_count); i++) {
            (*info) = (*info) + 1;
        }
        info = info - (*info_count);
        (*info_count)--;
        printf("Removed analyst from list\n");
    }
    return 0;
}
