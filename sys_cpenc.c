#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include "arg_struct.h"
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <linux/string.h>
#include <crypto/skcipher.h>

#define MD5_LENGTH  17

#define PAGE_SIZES 4096

#define EXTRA_CREDIT 1

asmlinkage extern long (*sysptr)(void *arg);

void key_to_password_encrypt(char *password, int len, char *output)
{
	struct scatterlist sg[2];
	struct crypto_ahash *tfm = NULL;
	struct ahash_request *req = NULL;

	if (!output)
		goto end;
	sg_init_one(sg, password, len);
	tfm = crypto_alloc_ahash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		goto end;
	req = ahash_request_alloc(tfm, GFP_ATOMIC);
	if (!req)
		goto end;
	ahash_request_set_callback(req, 0, NULL, NULL);
	ahash_request_set_crypt(req, sg, output, len);
	if (crypto_ahash_digest(req))
		goto end;
	output[MD5_LENGTH - 1] = '\0';
	pr_info("%s\n", output);
end:
	if (req)
		ahash_request_free(req);
	if (tfm)
		crypto_free_ahash(tfm);
}

struct skcipher_def {
	struct scatterlist sg;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct crypto_wait wait;
};

static unsigned int skcipher_encdec(struct skcipher_def *sk, int flag)
{
	int rc;

	if (flag == 1)
		rc = crypto_skcipher_encrypt(sk->req);
	else
		rc = crypto_skcipher_decrypt(sk->req);

	if (rc)
		pr_info("skcipher encrypt returned with result %d\n", rc);

	return rc;
}

static int encrpytion_decryption_skcipher(char *scratchpad, char *password,
					  int length, int in_len, int flag,
					  int page_no, char *f_ino)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *ivdata = NULL;
	char *key = NULL;
	int ret = -EFAULT;
	//char *f_ino = NULL;
	char *f_pno = NULL;
#ifdef EXTRA_CREDIT
	//unsigned long inode_no = output_file->f_inode->i_ino;
	unsigned long page_no_l = (unsigned long)page_no;
#endif
	skcipher = crypto_alloc_skcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}
	if (crypto_skcipher_setkey(skcipher, password, length)) {
		pr_info("Unable to set the key\n");
		ret = -EAGAIN;
		goto out;
	}
	ivdata = kmalloc(16, GFP_KERNEL);
	if (!ivdata)
		goto out;
#ifdef EXTRA_CREDIT
	f_pno = kmalloc(sizeof(char) * 8, GFP_KERNEL);
	if (!f_pno)
		goto out;
	sprintf(f_pno, "%08lu", page_no_l);
	memcpy(ivdata, f_pno, 8);
	//	f_ino = (char *)kmalloc(sizeof(char) * 8, GFP_KERNEL);
	//	sprintf(f_ino, "%08lu", inode_no);
	memcpy(ivdata + 8, f_ino, 8);
#else
	memcpy(ivdata, "aravindreddyravu", 16);
#endif
	sk.tfm = skcipher;
	sk.req = req;

	sg_init_one(&sk.sg, scratchpad, in_len);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, in_len, ivdata);
	ret = skcipher_encdec(&sk, flag);
	if (ret)
		goto out;
out:
#ifdef EXTRA_CREDIT
	//	if (f_ino)
	//		kfree(f_ino);
	kfree(f_pno);
#endif
	kfree(ivdata);
	kfree(key);
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	return ret;
}

unsigned long long  minimum(unsigned long long page_size,
			    unsigned long long rem_file_size)
{
	if (page_size < rem_file_size)
		return page_size;
	return rem_file_size;
}

static int is_file_regular(struct file *in_file)
{
	struct inode *fp_inode = in_file->f_inode;

	return !S_ISREG(fp_inode->i_mode);
}

int vfs_unlink_file(struct file *outfile_filp)
{
	int ret = -EACCES;

	pr_info("Deleting partially written out file\n");
	inode_lock_nested(outfile_filp->f_path.dentry->d_parent->d_inode,
			  I_MUTEX_PARENT);
	vfs_unlink(outfile_filp->f_path.dentry->d_parent->d_inode,
		   outfile_filp->f_path.dentry, NULL);
	inode_unlock(outfile_filp->f_path.dentry->d_parent->d_inode);
	return ret;
}

int file_encrypt_decrypt(INPUT_ARGUMENTS *kaddr, INPUT_ARGUMENTS *arg)
{
	int ret = 0;
	mm_segment_t oldfs;
	struct file *infile_filp = NULL;
	struct kstat infile_stat;
	struct kstat outfile_stat;
	unsigned long long  infile_offset = 0;
	unsigned long long infile_offset_itr = 0;
	char *infile_buf = NULL;
	unsigned long long infile_size = 0;
	unsigned long long min_size = 0;

	struct file *outfile_filp = NULL;
	unsigned long long output_offset = 0;
	char *output_keybuf = NULL;
	char *pswd_to_key = NULL;
	char *preamble_check = NULL;
	int page_no = 0;
	int start_enc_or_dec = 1;
	int file_flag = 0;
#ifdef EXTRA_CREDIT
	unsigned long inode_no;
	char *inode_char = NULL;
#endif
	//INPUT FILE PARSING;
	oldfs = get_fs();
	set_fs(get_ds());
	if (vfs_stat(arg->infile, &infile_stat) != 0) {
		pr_info("vfs_stat infile returned -ve value\n");
		ret = -EINVAL;
		goto end;
	}
	infile_size = infile_stat.size;
	//	oldfs = get_fs();
	//	set_fs(get_ds());
	infile_filp = filp_open(kaddr->infile, O_RDONLY, 0);
	set_fs(oldfs);
	if (!infile_filp || IS_ERR(infile_filp)) {
		ret  = PTR_ERR(infile_filp);
		//infile_filp = NULL;
		pr_info("filp_open input file error\n");
		goto end;
	}
	ret = is_file_regular(infile_filp);
	if (ret) {
		pr_info("Input file is not regular\n");
		ret = -EISDIR;
		goto end;
	}
	infile_offset = infile_filp->f_pos;
	infile_buf = kmalloc(sizeof(char) * PAGE_SIZES + 1, GFP_KERNEL);
	if (!infile_buf) {
		ret = -ENOMEM;
		goto end;
	}
	oldfs = get_fs();
	set_fs(get_ds());

	//OUTPUT FILE PARSING
	if (vfs_stat(arg->outfile, &outfile_stat) != 0) {
		pr_info("vfs_stat outfile returned -ve value\n");
		outfile_filp = filp_open(kaddr->outfile,
					 O_CREAT |  O_WRONLY | O_TRUNC,
					 infile_stat.mode);
	} else {
		outfile_filp = filp_open(kaddr->outfile,
					 O_WRONLY | O_TRUNC,
					 infile_stat.mode);
		file_flag = 1;
	}
	if (!outfile_filp || IS_ERR(outfile_filp)) {
		ret = PTR_ERR(outfile_filp);
		outfile_filp = NULL;
		pr_info("filp_open output file error\n");
		goto end;
	}
	if (file_flag == 1) {
		ret = is_file_regular(outfile_filp);
		if (ret) {
			pr_info("Output file is not regular\n");
			ret = -EISDIR;
			goto end;
		}
	}
	if (infile_filp->f_inode == outfile_filp->f_inode) {
		ret = -EINVAL;
		pr_info("Both the input and output files are pointing to same inode\n");
		goto end;
	}

	output_keybuf = kmalloc(sizeof(kaddr->keylen), GFP_KERNEL);
	if (!output_keybuf) {
		ret = -ENOMEM;
		goto end;
	}
	for (infile_offset_itr = infile_offset;
	     infile_offset_itr < infile_offset + infile_size ||
	     infile_size == 0;) {
		pr_info("Inside File Read Write Function\n");
		if (kaddr->flag == 4) {// COPYING ONE FILE TO ANOTHER
			if (infile_size == 0)
				break;
			pr_info("Key buf is %s\n", kaddr->keybuf);
			min_size = minimum((unsigned long long)PAGE_SIZES,
					   infile_size - infile_offset_itr);
			if (min_size == PAGE_SIZES)
				ret = vfs_read(infile_filp, infile_buf,
					       PAGE_SIZES, &infile_offset_itr);
			else
				ret = vfs_read(infile_filp, infile_buf,
					       min_size, &infile_offset_itr);

			if (ret >= 0)
				ret = 0;
			if (ret < 0) {
				pr_info("Deleting partially written out file\n");
				ret = vfs_unlink_file(outfile_filp);
				goto end;
			}
			if (infile_offset_itr % PAGE_SIZES == 0) {
				infile_buf[PAGE_SIZES] = '\0';
				ret = vfs_write(outfile_filp, infile_buf,
						PAGE_SIZES, &output_offset);
				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
			} else {
				infile_buf[min_size] = '\0';
				ret = vfs_write(outfile_filp, infile_buf,
						min_size, &output_offset);
				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
			}
		} else if (kaddr->flag == 1) {// ENCRYPTION
			if (start_enc_or_dec == 1) {
				start_enc_or_dec = 0;
				pswd_to_key  = kmalloc(MD5_LENGTH, GFP_KERNEL);
				if (!pswd_to_key) {
					ret = -ENOMEM;
					goto end;
				}
				key_to_password_encrypt(kaddr->keybuf,
							kaddr->keylen,
							pswd_to_key);
				ret = vfs_write(outfile_filp, pswd_to_key,
						MD5_LENGTH - 1, &output_offset);
				pr_info("In Encrypt : %s\n", pswd_to_key);
				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
#ifdef EXTRA_CREDIT
				inode_no = infile_filp->f_inode->i_ino;
				inode_char = kmalloc(8, GFP_KERNEL);
				if (!inode_char) {
					ret = -ENOMEM;
					goto end;
				}
				sprintf(inode_char, "%08lu", inode_no);
				ret = vfs_write(outfile_filp, inode_char, 8,
						&output_offset);
				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
#endif
			}
			if (infile_size == 0)
				break;
			min_size = minimum((unsigned long long)PAGE_SIZES,
					   infile_size - infile_offset_itr);
			if (min_size == PAGE_SIZES)
				ret = vfs_read(infile_filp, infile_buf,
					       PAGE_SIZES, &infile_offset_itr);
			else
				ret = vfs_read(infile_filp, infile_buf,
					       min_size, &infile_offset_itr);

			if (ret >= 0)
				ret = 0;
			if (ret < 0) {
				pr_info("Deleting partially written out file\n");
				ret = vfs_unlink_file(outfile_filp);
				goto end;
			}

#ifdef EXTRA_CREDIT
			ret = encrpytion_decryption_skcipher(infile_buf,
							     kaddr->keybuf,
							     kaddr->keylen,
							     min_size,
							     kaddr->flag,
							     page_no,
							     inode_char);
#else
			ret = encrpytion_decryption_skcipher(infile_buf,
							     kaddr->keybuf,
							     kaddr->keylen,
							     min_size,
							     kaddr->flag, 0,
							     NULL);
#endif
			if (ret != 0) {
				pr_info("Error while Encrypting the file at skcipher\n");
				ret = -EINVAL;
				goto end;
			}
			if (infile_offset_itr % PAGE_SIZES == 0) {
				infile_buf[PAGE_SIZES] = '\0';
				ret = vfs_write(outfile_filp, infile_buf,
						PAGE_SIZES, &output_offset);

				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
			} else {
				infile_buf[min_size] = '\0';
				ret = vfs_write(outfile_filp, infile_buf,
						min_size, &output_offset);
				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = -EACCES;
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
			}
			page_no++;
		} else	{//DECRYPTION
			if (start_enc_or_dec == 1) {
				start_enc_or_dec = 0;
				preamble_check = kmalloc(MD5_LENGTH,
							 GFP_KERNEL);
				if (!preamble_check) {
					ret = -ENOMEM;
					goto end;
				}
				pswd_to_key  = kmalloc(MD5_LENGTH, GFP_KERNEL);
				if (!pswd_to_key) {
					ret = -ENOMEM;
					goto end;
				}
				ret = vfs_read(infile_filp, preamble_check,
					       MD5_LENGTH - 1,
					       &infile_offset_itr);
				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
				preamble_check[MD5_LENGTH - 1] = '\0';
				pr_info("In Decrypt\n");
				pr_info("Preamble : %s\n", preamble_check);
				key_to_password_encrypt(kaddr->keybuf,
							kaddr->keylen,
							pswd_to_key);
				pr_info("Password : %s\n", pswd_to_key);
				if (strcmp(pswd_to_key, preamble_check) != 0) {
					pr_info("Decryption key doesn't match with the key passed from user\n");
					ret = -EINVAL;
					goto end;
				}
#ifdef EXTRA_CREDIT
				inode_char = kmalloc(8 * sizeof(char),
						     GFP_KERNEL);
				if (!inode_char) {
					ret = -ENOMEM;
					goto end;
				}
				ret = vfs_read(infile_filp, inode_char,
					       8, &infile_offset_itr);
				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
#endif
			}
			if (infile_size == 0)
				break;
			min_size = minimum((unsigned long long)PAGE_SIZES,
					   infile_size - infile_offset_itr);
			if (min_size == PAGE_SIZES)
				ret = vfs_read(infile_filp, infile_buf,
					       PAGE_SIZES, &infile_offset_itr);
			else
				ret = vfs_read(infile_filp, infile_buf,
					       min_size, &infile_offset_itr);

			if (ret >= 0)
				ret = 0;
			if (ret < 0) {
				pr_info("Deleting partially written out file\n");
				ret = vfs_unlink_file(outfile_filp);
				goto end;
			}

#ifdef EXTRA_CREDIT
			ret = encrpytion_decryption_skcipher(infile_buf,
							     kaddr->keybuf,
							     kaddr->keylen,
							     min_size,
							     kaddr->flag,
							     page_no,
							     inode_char);
#else
			ret = encrpytion_decryption_skcipher(infile_buf,
							     kaddr->keybuf,
							     kaddr->keylen,
							     min_size,
							     kaddr->flag, 0,
							     NULL);
#endif

			if (ret != 0) {
				pr_info("Error while Encrypting the file at skcipher\n");
				ret = -EINVAL;
				goto end;
			}
			if (infile_offset_itr % PAGE_SIZES == 0) {
				infile_buf[PAGE_SIZES] = '\0';
				ret = vfs_write(outfile_filp, infile_buf,
						PAGE_SIZES, &output_offset);
				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
			} else {
				infile_buf[min_size] = '\0';
				ret = vfs_write(outfile_filp, infile_buf,
						min_size, &output_offset);
				if (ret < 0) {
					pr_info("Deleting partially written out file\n");
					ret = vfs_unlink_file(outfile_filp);
					goto end;
				}
				if (ret > 0)
					ret = 0;
			}
			page_no++;
		}
	}
	//set_fs(oldfs);
end:
#ifdef EXTRA_CREDIT
	kfree(inode_char);
#endif
	//pr_info("Hereh\n");
	//if (output)
	//	kfree(output);
	kfree(preamble_check);
	kfree(pswd_to_key);
	if (outfile_filp)
		filp_close(outfile_filp, NULL);
	kfree(infile_buf);
	if (infile_filp)
		filp_close(infile_filp, NULL);
	kfree(output_keybuf);
	set_fs(oldfs);
	return ret;
}

asmlinkage long cpenc(void *arg)
{
	//Check if password and copy -c is given
	INPUT_ARGUMENTS *kaddr = NULL;
	int ret = 0;
	struct filename *inputfile_struct = NULL;
	struct filename *outputfile_struct = NULL;
	struct filename *keybuf_struct = NULL;
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */

	if (!arg)
		return -EINVAL;
	pr_info("%s received arg %p\n", __func__, arg);
	if (access_ok(VERIFY_READ, arg, sizeof(INPUT_ARGUMENTS)) == 0) {
		pr_info("The user space address is invalid inside access_ok() of arg\n");
		ret =  -EFAULT;
		goto end;
	}
	kaddr = kmalloc(sizeof(INPUT_ARGUMENTS), GFP_KERNEL);

	if (!kaddr) {
		ret =  -ENOMEM;
		goto end;
	}

	if (copy_from_user((void *)kaddr, arg, sizeof(INPUT_ARGUMENTS)) != 0) {
		pr_info("Error in copying kaddr");
		ret = -EFAULT;
		goto end;
	}
	if (kaddr->flag == 0) {
		pr_info("Set flag to specify whether to Encrpyt/Decrypt/Copy\n");
		ret = -EINVAL;
		goto end;
	}
	pr_info("kaddr->flag is %d\n", kaddr->flag);
	if (kaddr->flag != 1 && kaddr->flag != 2 && kaddr->flag != 4) {
		pr_info("Invalid flag passed which should be 1,2,4\n");
		ret = -EINVAL;
		goto end;
	}

	if (kaddr->flag != 4 && kaddr->keylen < 6) {
		pr_info("The length of password is %d\n", kaddr->keylen);
		pr_info("The keybuf should be atleast 6 characters\n");
		ret = -EINVAL;
		goto end;
	}
	if (kaddr->flag != 4) {
		if (!kaddr->keybuf) {
			pr_info("Error in user space keybuf\n");
			ret = -EINVAL;
			goto end;
		}
		if (access_ok(VERIFY_READ, kaddr->keybuf, kaddr->keylen) == 0) {
			pr_info("The user space address is invalid inside keybuf\n");
			ret = -EFAULT;
			goto end;
		}

		keybuf_struct = getname(kaddr->keybuf);
		if (!keybuf_struct) {
			pr_info("Erro in user space kaddr->keybuf\n");
			ret = -EINVAL;
			goto end;
		}
		kaddr->keybuf = (char *)keybuf_struct->name;
		pr_info("Keybuf is : %s\n", kaddr->keybuf);
	}

	if (!kaddr->infile) {
		pr_info("Error in user space infile %s\n", kaddr->infile);
		ret = -EINVAL;
		goto end;
	}
	if (access_ok(VERIFY_READ, kaddr->infile, kaddr->infile_length) == 0) {
		pr_info("The user space address is invalid inside infile\n");
		ret = -EFAULT;
		goto end;
	}

	inputfile_struct = getname(kaddr->infile);
	if (!inputfile_struct) {
		pr_info("Erro in user space kaddr->infile\n");
		ret = -EINVAL;
		goto end;
	}
	kaddr->infile = (char *)inputfile_struct->name;
	pr_info("Input File is : %s\n", kaddr->infile);

	if (!kaddr->outfile) {
		pr_info("Error in user space outfile\n");
		ret = -EINVAL;
		goto end;
	}
	if (access_ok(VERIFY_READ, kaddr->outfile,
		      kaddr->outfile_length) == 0) {
		pr_info("The user space address is invalid inside output file\n");
		ret = -EFAULT;
		goto end;
	}

	outputfile_struct = getname(kaddr->outfile);
	if (!outputfile_struct) {
		pr_info("Erro in user space kaddr->outfile\n");
		ret = -EINVAL;
		goto end;
	}
	kaddr->outfile = (char *)outputfile_struct->name;
	pr_info("Output File is : %s\n", kaddr->outfile);
	if (strcmp(kaddr->infile, kaddr->outfile) == 0) {
		pr_info("Input file and Output File are the same\n");
		ret = -EINVAL;
		goto end;
	}
	if (kaddr->flag == 4 && kaddr->keylen > 0) {
		pr_info("Copying a file doesn't require password\n");
		ret = -EINVAL;
		goto end;
	}
	if (file_encrypt_decrypt(kaddr, (INPUT_ARGUMENTS *)arg) != 0) {
		pr_info("Error opening file\n");
		ret = -EINVAL;
		goto end;
	}
end:
	if (outputfile_struct)
		putname(outputfile_struct);
	if (keybuf_struct)
		putname(keybuf_struct);
	if (inputfile_struct)
		putname(inputfile_struct);
	kfree(kaddr);
	return ret;
	// Free kaddr
}

static int __init init_sys_cpenc(void)
{
	pr_info("installed new sys_cpenc module\n");
	if (!sysptr)
		sysptr = cpenc;
	return 0;
}

static void  __exit exit_sys_cpenc(void)
{
	if (sysptr)
		sysptr = NULL;
	pr_info("removed sys_cpenc module\n");
}
module_init(init_sys_cpenc);
module_exit(exit_sys_cpenc);
MODULE_LICENSE("GPL");
