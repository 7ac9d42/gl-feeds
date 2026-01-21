#include <linux/module.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/etherdevice.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/ubi.h>
#include <linux/blkdev.h>
#include <linux/version.h>
#include <linux/pagemap.h>

#include "gl-hw-info.h"

static int block_part_read(const char *part, unsigned int from,
                           void *val, size_t bytes)
{
    pgoff_t index = from >> PAGE_SHIFT;
    int offset = from & (PAGE_SIZE - 1);
    struct address_space *mapping;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
    const blk_mode_t mode = BLK_OPEN_READ;
    struct file *bdev_file;
#else
    const fmode_t mode = FMODE_READ;
    struct block_device *bdev;
#endif
    struct page *page;
    char *buf = val;
    int cpylen;
    int ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
    bdev_file = bdev_file_open_by_path(part, mode, NULL, NULL);
    if (IS_ERR(bdev_file))
        return PTR_ERR(bdev_file);

    mapping = bdev_file->f_mapping;
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    bdev = blkdev_get_by_path(part, mode, NULL);
#else
    bdev = blkdev_get_by_path(part, mode, NULL, NULL);
#endif
    if (IS_ERR(bdev))
        return PTR_ERR(bdev);

    mapping = bdev->bd_inode->i_mapping;
#endif

    while (bytes) {
        if ((offset + bytes) > PAGE_SIZE)
            cpylen = PAGE_SIZE - offset;
        else
            cpylen = bytes;
        bytes = bytes - cpylen;

        page = read_mapping_page(mapping, index, NULL);
        if (IS_ERR(page)) {
            ret = PTR_ERR(page);
            goto out;
        }

        memcpy(buf, page_address(page) + offset, cpylen);
        put_page(page);

        buf += cpylen;
        offset = 0;
        index++;
    }

out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
    fput(bdev_file);
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    blkdev_put(bdev, mode);
#else
    blkdev_put(bdev, NULL);
#endif
#endif

    return ret;
}

static int parse_mtd_value(const char *part, u32 offset, void *dest, int len)
{
#ifdef CONFIG_MTD
    struct mtd_info *mtd;
    size_t retlen;
    int rc;

    mtd = get_mtd_device_nm(part);
    if (IS_ERR(mtd))
        return -1;

    rc = mtd_read(mtd, offset, len, &retlen, dest);
    if (!rc && retlen != len)
        rc = -EIO;

    put_mtd_device(mtd);
    return rc;
#else
    return -ENODEV;
#endif
}

static int parse_ubi_value(const char *part, u32 offset, void *dest, int len)
{
#ifdef CONFIG_MTD_UBI
    struct ubi_volume_desc *desc;
    size_t retlen;
    int rc = 0;

    desc = ubi_open_volume_path(part, UBI_READONLY);
    if (IS_ERR(desc)) {
        return -1;
    }
    retlen = ubi_read(desc, 0, dest, offset, len);
    if (retlen) {
        rc = -EIO;
    }

    ubi_close_volume(desc);
    return rc;
#else
    return -ENODEV;
#endif
}

static int parse_value(struct device_node *np, const char *prop,
                       void *dest, int len)
{
    const char *part, *offset_str;
    u32 offset = 0;

    if (of_property_read_string_index(np, prop, 0, &part))
        return -1;

    if (!of_property_read_string_index(np, prop, 1, &offset_str))
        offset = simple_strtoul(offset_str, NULL, 0);

    if (!strncmp(part, "/dev/ubi", 8))
        return parse_ubi_value(part, offset, dest, len);

    if (!strncmp(part, "/dev/mmc", 8))
        return block_part_read(part, offset, dest, len);

    return parse_mtd_value(part, offset, dest, len);
}

static void make_device_country_code(struct device_node *np)
{
    __be16 country_code = 0;

    if (parse_value(np, "country_code", &country_code, COUNTRY_LEN))
        return;

    create_proc_node("country_code", lookup_country(be16_to_cpu(country_code)));
}

static void make_device_sn_bak(struct device_node *np)
{
    if (parse_value(np, "device_sn_bak", gl_hw_info.device_sn_bak, SN_LEN))
        return;

    if (strlen(gl_hw_info.device_sn_bak))
        create_proc_node("device_sn_bak", gl_hw_info.device_sn_bak);
}

static void make_device_sn(struct device_node *np)
{
    if (parse_value(np, "device_sn", gl_hw_info.device_sn, SN_LEN))
        return;

    if (strlen(gl_hw_info.device_sn))
        create_proc_node("device_sn", gl_hw_info.device_sn);
}

static void make_device_ddns(struct device_node *np)
{
    if (parse_value(np, "device_ddns", gl_hw_info.device_ddns, DDNS_LEN))
        return;

    if (strlen(gl_hw_info.device_ddns))
        create_proc_node("device_ddns", gl_hw_info.device_ddns);
}

static void make_device_mac(struct device_node *np)
{
    u8 mac[ETH_ALEN];

    if (parse_value(np, "device_mac", mac, MAC_LEN))
        return;

    if (is_valid_ether_addr(mac)) {
        snprintf(gl_hw_info.device_mac, sizeof(gl_hw_info.device_mac), "%pM", mac);
        create_proc_node("device_mac", gl_hw_info.device_mac);
    }
}

static void make_device_cert(struct device_node *np)
{
    size_t key_len;
    char *p;

    if (parse_value(np, "device_cert", gl_hw_info.device_cert, CERT_LEN))
        return;

    p = strstr(gl_hw_info.device_cert, "-----BEGIN PRIVATE KEY-----");
    if (!p)
        return;

    key_len = strlen(p);

    if (p[key_len - 1] == '\n')
        p[key_len - 1] = '\0';

    memmove(p + 1, p, key_len);

    if (p[-1] == '\n')
        p[-1] = '\0';

    *p++ = '\0';

    gl_hw_info.device_key = p;

    create_proc_node("device_cert", gl_hw_info.device_cert);
    create_proc_node("device_key", gl_hw_info.device_key);
}

static void make_device_submodel(struct device_node *np)
{
    size_t submodel_len = 0;
    size_t i;
    bool all_ff = true;
    u8 *p;

    if (parse_value(np, "device_submodel", gl_hw_info.device_submodel, SUBMODEL_LEN))
        return;

    p = gl_hw_info.device_submodel;

    /* Check if the submodel is empty padding (0xff/0x00) */
    for (i = 0; i < SUBMODEL_LEN; i++) {
        if (p[i] != 0xff && p[i] != 0x00) {
            all_ff = false;
            break;
        }
    }

    if (all_ff) {
        gl_hw_info.device_submodel[0] = '\0';
        goto out;
    }

    /* Find first 0xff/0x00 padding byte and terminate there */
    submodel_len = SUBMODEL_LEN;
    for (i = 0; i < SUBMODEL_LEN; i++) {
        if (p[i] == 0xff || p[i] == 0x00) {
            submodel_len = i;
            break;
        }
    }
    gl_hw_info.device_submodel[submodel_len] = '\0';

out:

    create_proc_node("device_submodel", gl_hw_info.device_submodel);
}

static void make_firmware_type_flag(struct device_node *np)
{
    if (parse_value(np, "firmware_type", gl_hw_info.firmware_type, FIRMWARE_LEN))
        return;

    if (strlen(gl_hw_info.firmware_type) && gl_hw_info.firmware_type[0] == '2' && gl_hw_info.firmware_type[1] == 'b')
        create_proc_node("firmware_type", gl_hw_info.firmware_type);
    else
        create_proc_node("firmware_type", "2c");
}

void make_factory_data(struct device_node *np)
{
    make_device_mac(np);
    make_device_ddns(np);
    make_device_sn(np);
    make_device_sn_bak(np);
    make_device_cert(np);
    make_device_country_code(np);
    make_device_submodel(np);
    make_firmware_type_flag(np);
}
