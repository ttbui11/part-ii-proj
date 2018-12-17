//
// Copyright (c) 2017 Stephen Ibanez
// All rights reserved.
//
// This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
// under National Science Foundation under Grant No. CNS-0855268,
// the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
// by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
// as part of the DARPA MRC research programme.
//
// @NETFPGA_LICENSE_HEADER_START@
//
// Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
// license agreements.  See the NOTICE file distributed with this work for
// additional information regarding copyright ownership.  NetFPGA licenses this
// file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
// "License"); you may not use this file except in compliance with the
// License.  You may obtain a copy of the License at:
//
//   http://www.netfpga-cic.org
//
// Unless required by applicable law or agreed to in writing, Work distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations under the License.
//
// @NETFPGA_LICENSE_HEADER_END@
//


/*
 *  File:
 *        sume_reg_if.h
 *
 * Author:
 *        Stephen Ibanez
 *
 */

#ifndef SUME_REG_IF_H_
#define SUME_REG_IF_H_

#define	SUME_DEFAULT_TEST_ADDR		0x44020000

typedef unsigned int uint32_t;

/*
 Helper function for the functions listed below
*/
uint32_t sume_register_if(uint32_t addr, uint32_t data, int req);

/*
Arguments   :  addr - the address of the register to write to
               data - the data to write to the register 
return      :  void
Description :  user-level function to write data to particular addresses
*/
void sume_register_write(uint32_t addr, uint32_t data);

/*
Arguments   :  addr - the address of the register to read from
return      :  value of the register
Description :  user-level function to read data from particular addresses 
*/
uint32_t sume_register_read(uint32_t addr);

#endif

