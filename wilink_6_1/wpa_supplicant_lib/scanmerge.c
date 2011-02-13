/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*-------------------------------------------------------------------*/
#include "includes.h"
#include "scanmerge.h"
#include "shlist.h"

/*-----------------------------------------------------------------------------
Routine Name: scan_init
Routine Description: Inits scan merge list
Arguments:
   mydrv   - pointer to private driver data structure
Return Value:
-----------------------------------------------------------------------------*/
void scan_init( struct wpa_driver_ti_data *mydrv )
{
    mydrv->last_scan = -1;
    shListInitList( &(mydrv->scan_merge_list) );
}

/*-----------------------------------------------------------------------------
Routine Name: scan_free
Routine Description: Frees scan structure private data
Arguments:
   ptr - pointer to private data structure
Return Value:
-----------------------------------------------------------------------------*/
static void scan_free( void *ptr )
{
    scan_merge_t *scan_ptr = (scan_merge_t *)ptr;
    os_free(scan_ptr->scanres);
    os_free(scan_ptr);
}

/*-----------------------------------------------------------------------------
Routine Name: scan_exit
Routine Description: Cleans scan merge list
Arguments:
   mydrv   - pointer to private driver data structure
Return Value:
-----------------------------------------------------------------------------*/
void scan_exit( struct wpa_driver_ti_data *mydrv )
{
    shListDelAllItems( &(mydrv->scan_merge_list), scan_free );
}

/*-----------------------------------------------------------------------------
Routine Name: is_hidden_ap
Routine Description: Check if it is a SSID-hidden AP
Arguments:
   res_ptr   - pointer to scan result structure
Return Value:
-----------------------------------------------------------------------------*/
static int is_hidden_ap( struct wpa_scan_res *res_ptr )
{
    const u8 *ie;
    ie = wpa_scan_get_ie(res_ptr, WLAN_EID_SSID);
    if((NULL == ie) || (ie[1] == 0) || (ie[2] == '\0')) {
        return 1;
    }

    return 0;
}

/*-----------------------------------------------------------------------------
Routine Name: copy_hidden_ap_ssid
Routine Description: Copy/update the hidden ap SSID field
Arguments:
   res   - pointer to scan results structure
   i   - the index of the scan result
   res_ptr   - pointer to scan result structure that has the SSID field
Return Value:
-----------------------------------------------------------------------------*/
static void copy_hidden_ap_ssid( struct wpa_scan_results *res, int i, struct wpa_scan_res *res_ptr )
{
    struct wpa_scan_res *r;
    size_t ssid_ie_len, ie_len;
    const u8 *ssid_ie;
    u8 *pos, *end, *p;

    /* Get the ie length with new SSID ie */
    ssid_ie_len = 0;
    ssid_ie = wpa_scan_get_ie(res->res[i], WLAN_EID_SSID);
    if (ssid_ie != NULL) {
        ssid_ie_len = 2 + ssid_ie[1];
    }
    ie_len = res->res[i]->ie_len - ssid_ie_len;

    ssid_ie_len = 0;
    ssid_ie = wpa_scan_get_ie(res_ptr, WLAN_EID_SSID);
    if (ssid_ie != NULL) {
        ssid_ie_len = 2 + ssid_ie[1];
    }
    ie_len += ssid_ie_len;

    r = (struct wpa_scan_res*)os_malloc(sizeof(*r) + ie_len);
    if (r == NULL)
        return;

    os_memcpy(r, res->res[i], sizeof(*r));
    r->ie_len = ie_len;

    /* Copy the ssid ie */
    p = (u8 *) (r + 1);
    if (ssid_ie != NULL) {
        os_memcpy(p, ssid_ie, ssid_ie_len);
        p += ssid_ie_len;
    }

    /* Copy other IEs except the SSID */
    pos = (u8 *)(res->res[i]) + sizeof(*r);
    end = pos + res->res[i]->ie_len;
    while (pos && pos + 1 < end) {
        if (pos + 2 + pos[1] > end)
            break;
        if (pos[0] != WLAN_EID_SSID) {
            os_memcpy(p, pos, 2 + pos[1]);
            p += 2 + pos[1];
        }
        pos += 2 + pos[1];
    }

    /* Replace it with new scan_result */
    os_free(res->res[i]);
    res->res[i] = r;
    return;
}

/*-----------------------------------------------------------------------------
Routine Name: scan_equal
Routine Description: Compares bssid of scan result and scan merge structure
Arguments:
   val   - pointer to scan result structure
   idata - pointer to scan merge structure
Return Value: 1 - if equal, 0 - if not
-----------------------------------------------------------------------------*/
static int scan_equal( void *val,  void *idata )
{
    struct wpa_scan_res *new_res;
    struct wpa_scan_res *lst_res;
    const u8 *new_ie, *lst_ie;

    if( (NULL == val) || (NULL == idata)) {
        return 0;
    }

    new_res = (struct wpa_scan_res *)val;
    lst_res = (struct wpa_scan_res *)(((scan_merge_t *)idata)->scanres);

    if(os_memcmp(new_res->bssid, lst_res->bssid, ETH_ALEN)) {
        return 0;
    }

    if(is_hidden_ap(new_res) || is_hidden_ap(lst_res)) {
        return 1;
    }

    new_ie = wpa_scan_get_ie(new_res, WLAN_EID_SSID);
    if(NULL == new_ie) {
        return 1;
    }

    lst_ie = wpa_scan_get_ie(lst_res, WLAN_EID_SSID);
    if(NULL == lst_ie) {
        return 1;
    }

    if((new_ie[1] != lst_ie[1]) || os_memcmp((void*)(new_ie+2), (void*)(lst_ie+2), (int)new_ie[1])) {
        return 0;
    }

    return 1;
}

/*-----------------------------------------------------------------------------
Routine Name: scan_add
Routine Description: adds scan result structure to scan merge list
Arguments:
   head    - pointer to scan merge list head
   res_ptr - pointer to scan result structure
Return Value: Pointer to scan merge item
-----------------------------------------------------------------------------*/
static scan_merge_t *scan_add( SHLIST *head, struct wpa_scan_res *res_ptr )
{
    size_t size;
    scan_merge_t *scan_ptr;

    scan_ptr = (scan_merge_t *)os_malloc( sizeof(scan_merge_t) );
    if( NULL == scan_ptr )
        return( NULL );

    size = sizeof(struct wpa_scan_res) + res_ptr->ie_len;
    scan_ptr->scanres = (struct wpa_scan_res*)os_malloc( size );
    if( NULL == scan_ptr->scanres ) {
        os_free( scan_ptr );
        return( NULL );
    }

    os_memcpy( scan_ptr->scanres, res_ptr, size );
    scan_ptr->count = SCAN_MERGE_COUNT;
    shListInsLastItem( head, (void *)scan_ptr );
    return scan_ptr;
}

/*-----------------------------------------------------------------------------
Routine Name: scan_find
Routine Description: Looks for scan merge item in scan results array
Arguments:
   scan_ptr - pointer to scan merge item
   results - pointer to scan results array
   number_items - current number of items
Return Value: 1 - if item was found, 0 - otherwise
-----------------------------------------------------------------------------*/
static int scan_find( scan_merge_t *scan_ptr, struct wpa_scan_results *res )
{
    unsigned int i;

    if( NULL == res ) {
        return 0;
    }

    for(i=0; i < res->num; i++) {
        if( scan_equal( res->res[i], scan_ptr ) )
            return 1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------
Routine Name: scan_merge
Routine Description: Merges current scan results with previous
Arguments:
   mydrv   - pointer to private driver data structure
   results - pointer to scan results
Return Value: pointer to the merged scan results
-----------------------------------------------------------------------------*/
void scan_merge( struct wpa_driver_ti_data *mydrv, struct wpa_scan_results *res, int force_flag )
{
    SHLIST *head = &(mydrv->scan_merge_list);
    SHLIST *item, *del_item;
    scan_merge_t *scan_ptr;
    struct wpa_scan_res **tmp;
    struct wpa_scan_res *r;
    size_t size;
    unsigned int i;

    struct wpa_scan_res *res_associated;
    struct wpa_supplicant *wpa_s;
    const u8 *bssid;

    if( NULL == res ) {
        return;
    }

    for(i=0; i < res->num; i++) {
        size = sizeof(struct wpa_scan_res) + res->res[i]->ie_len;
        wpa_printf(MSG_MSGDUMP, "ScanResult %d", i+1);
        wpa_hexdump_ascii(MSG_MSGDUMP, "AsciiScanResult", (const u8*)(res->res[i]), size);
    }

    res_associated = NULL;
    wpa_s = (struct wpa_supplicant *)(mydrv->ctx);
    bssid = wpa_s->bssid;
    if (!is_zero_ether_addr(bssid)) { /* Current associated bssid */
        for(i=0; i < res->num; i++) { /* Find the item in the scan-results */
            if( !os_memcmp(res->res[i]->bssid, bssid, ETH_ALEN) )
                break;
        }

        if (i >= res->num) { /* Not find the item in scan-results */
            r = scan_get_by_bssid( mydrv, (u8 *)bssid ); /* Find the item in scan cache */
            if (NULL != r) { /* Backup the item in r */
                size = sizeof(struct wpa_scan_res) + r->ie_len;
                res_associated = (struct wpa_scan_res*)os_malloc( size );
                if( NULL != res_associated ) {
                    os_memcpy( res_associated, r, size );

                    wpa_printf(MSG_INFO, "Append the associated ap to scan_results, BSSID=" MACSTR, MAC2STR(bssid));
                    tmp = os_realloc(res->res, (res->num + 1) * sizeof(struct wpa_scan_res *));
                    if( NULL != tmp ) {
                        tmp[res->num++] = res_associated;
                        res->res = tmp;
                    } else {
                        os_free( res_associated );
                        res_associated = NULL;
                    }
                }
            }
        }
    }

    /* Prepare items for removal */
    item = shListGetFirstItem( head );
    while( item != NULL ) {
        scan_ptr = (scan_merge_t *)(item->data);
        if( scan_ptr->count != 0 )
            scan_ptr->count--;
        item = shListGetNextItem( head, item );
    }

    for(i=0; i < res->num; i++) { /* Find/Add new items */
        item = shListFindItem( head, res->res[i], scan_equal );
        if( item ) {
            scan_ptr = (scan_merge_t *)(item->data);

            if( is_hidden_ap(res->res[i]) && !is_hidden_ap(scan_ptr->scanres) ) {
                copy_hidden_ap_ssid(res, i, scan_ptr->scanres);
            }

            size = sizeof(struct wpa_scan_res) + res->res[i]->ie_len;
            r = (struct wpa_scan_res*)os_malloc( size );
            if( NULL == r ) {
                return;
            }
            os_memcpy( r, res->res[i], size );

            os_free(scan_ptr->scanres);
            scan_ptr->scanres = r;
            scan_ptr->count = SCAN_MERGE_COUNT;
        } else {
            if( NULL == scan_add( head, res->res[i] )) {
                return;
            }
        }
    }

    item = shListGetFirstItem( head );  /* Add/Remove missing items */
    while( item != NULL ) {
        del_item = NULL;
        scan_ptr = (scan_merge_t *)(item->data);
        if( scan_ptr->count != SCAN_MERGE_COUNT ) {
            if( !force_flag && ((scan_ptr->count == 0) ||
                (mydrv->last_scan == SCAN_TYPE_NORMAL_ACTIVE)) )
                del_item = item;
            else {
                size = sizeof(struct wpa_scan_res) + scan_ptr->scanres->ie_len;
                r = (struct wpa_scan_res*)os_malloc( size );
                if( NULL == r ) {
                    return;
                }
                os_memcpy( r, scan_ptr->scanres, size );

                tmp = os_realloc(res->res, (res->num + 1) * sizeof(struct wpa_scan_res *));
                if( NULL == tmp ) {
                    os_free( r );
                    return;
                }

                tmp[res->num++] = r;
                res->res = tmp;
            }
        }
        item = shListGetNextItem( head, item );

        if( del_item != NULL ) {
            shListDelItem( head, del_item, scan_free );
        }
    }

    return;
}

/*-----------------------------------------------------------------------------
Routine Name: scan_get_by_bssid
Routine Description: Gets scan_result pointer to item by bssid
Arguments:
   mydrv   - pointer to private driver data structure
   bssid   - pointer to bssid value
Return Value: pointer to scan_result item
-----------------------------------------------------------------------------*/
struct wpa_scan_res *scan_get_by_bssid( struct wpa_driver_ti_data *mydrv,
                         u8 *bssid )
{
    SHLIST *head = &(mydrv->scan_merge_list);
    SHLIST *item;
    struct wpa_scan_res *cur_res;

    item = shListGetFirstItem( head );  /* Add/Remove missing items */
    if( item == NULL )
        return( NULL );
    do {
        cur_res =((scan_merge_t *)(item->data))->scanres;
        if( (!os_memcmp(cur_res->bssid, bssid, ETH_ALEN)) &&
            (!is_hidden_ap(cur_res)) ) {
            return( cur_res );
        }
        item = shListGetNextItem( head, item );
    } while( item != NULL );

    return( NULL );
}
