//package main
package cglf

import "fmt"
import "github.com/abeconnelly/autoio"

import "strings"
import "strconv"

import "log"

//import "os"

type SGLFInfo struct {
  Path int
  Step int
  Variant int
  Span int
}

type SGLF struct {

  // path, step, array of tiles
  //
  Lib map[int]map[int][]string
  LibInfo map[int]map[int][]SGLFInfo

  MD5Lookup map[string]SGLFInfo
  PfxTagLookup map[string]SGLFInfo
  SfxTagLookup map[string]SGLFInfo
}

func LoadGenomeLibraryCSV(fn string) (SGLF,error) {
  sglf := SGLF{}
  sglf.Lib = make(map[int]map[int][]string)
  sglf.LibInfo = make(map[int]map[int][]SGLFInfo)

  ain,e := autoio.OpenReadScanner(fn)
  if e!=nil { return sglf, e }
  defer ain.Close()

  line_no:=-1

  sglf.MD5Lookup = make(map[string]SGLFInfo)
  sglf.PfxTagLookup = make(map[string]SGLFInfo)
  sglf.SfxTagLookup = make(map[string]SGLFInfo)

  prev_pfxtag := ""
  prev_sfxtag := ""
  prev_sglf_info := SGLFInfo{}
  prev_tilepath := -1

  // There's a corner case when we're at the last tile and
  // we add the sfx tag to SfxTagLookup.  If one's already
  // added, we can consult the 'can_overwrite' and notice that
  // we shouldn't overwrite it.  If we've added the sfxtag
  // to the SfxTagLookup but then later notice it's the last
  // tile, we can set the 'can_overwrite' entry to false
  // to allow the addition of a future sfxtag.
  //
  // Tags are unique so it might never come up but if
  // some variation at the end induces a run to be like a tag
  // we could run into problems (though we might have other
  // problems as well)
  //
  can_overwrite := make(map[string]bool)

  for ain.ReadScan() {
    line_no++
    l := ain.ReadText()
    if len(l)==0 { continue }
    if (l[0]==0) || (l[0]=='#') { continue }

    line_parts := strings.Split(l, ",")
    if len(line_parts)<3 { return sglf, fmt.Errorf("not enough CSV elements on line_no %d", line_no) }

    tileid_span_parts := strings.Split(line_parts[0], "+")
    if len(tileid_span_parts)!=2 { return sglf, fmt.Errorf("invalid tileid (%s) on line_no %d", line_parts[0], line_no) }

    tileid_parts := strings.Split(tileid_span_parts[0], ".")
    if len(tileid_parts)!=4 { return sglf, fmt.Errorf("invalid tileid (%s) on line_no %d", line_parts[0], line_no) }

    tilepath_l,e := strconv.ParseInt(tileid_parts[0], 16, 64)
    if e!=nil { return sglf, fmt.Errorf("%v: line_no %d\n", e, line_no) }

    tilestep_l,e := strconv.ParseInt(tileid_parts[2], 16, 64)
    if e!=nil { return sglf, fmt.Errorf("%v: line_no %d\n", e, line_no) }

    tilevar_l,e := strconv.ParseInt(tileid_parts[3], 16, 64)
    if e!=nil { return sglf, fmt.Errorf("%v: line_no %d\n", e, line_no) }

    tilespan_l,e := strconv.ParseInt(tileid_span_parts[1], 16, 64)
    if e!=nil { return sglf, fmt.Errorf("%v: line_no %d\n", e, line_no) }

    tilepath := int(tilepath_l)
    tilestep := int(tilestep_l)
    tilevar := int(tilevar_l)
    tilespan := int(tilespan_l)

    md5_str := line_parts[1]
    seq := line_parts[2]

    if len(seq) < 48 { return sglf, fmt.Errorf("len(seq)<48: line_no %d", line_no) }

    pfxtag := seq[:24]
    sfxtag := seq[len(seq)-24:]

    if _,ok := sglf.Lib[tilepath] ; !ok {
      sglf.Lib[tilepath] = make(map[int][]string)
      sglf.LibInfo[tilepath] = make(map[int][]SGLFInfo)
    }
    if _,ok := sglf.Lib[tilepath][tilestep] ; !ok {
      sglf.Lib[tilepath][tilestep] = make([]string, 0, 16)
      sglf.LibInfo[tilepath][tilestep] = make([]SGLFInfo, 0, 16)
    }
    sglf.Lib[tilepath][tilestep] = append(sglf.Lib[tilepath][tilestep], seq)
    sglf.LibInfo[tilepath][tilestep] = append(sglf.LibInfo[tilepath][tilestep], SGLFInfo{ Path: tilepath, Step: tilestep, Variant: tilevar, Span: tilespan } )

    sglf_info := SGLFInfo{ Path: int(tilepath), Step: int(tilestep), Variant: int(tilevar), Span: int(tilespan) }
    sglf.MD5Lookup[md5_str] = sglf_info

    if prev_pfxtag != "" { sglf.PfxTagLookup[prev_pfxtag] = prev_sglf_info }
    if prev_sfxtag != "" {

      if _,ok := can_overwrite[prev_sfxtag] ; !ok {

        // not in map, add it
        //
        sglf.SfxTagLookup[prev_sfxtag] = prev_sglf_info
      } else if can_overwrite[prev_sfxtag] {

        log.Printf("found suspicious tag (previously seen): '%s' at path.step.variant (%x.%x.%x)",
          prev_sfxtag, tilepath, tilestep, tilevar)

        // otherwise if we can overwrite it, do so
        //
        sglf.SfxTagLookup[prev_sfxtag] = prev_sglf_info

      }

      // Remember we've added this sfxtag
      //
      can_overwrite[prev_sfxtag] = false

    }

    prev_sfxtag = sfxtag
    if prev_tilepath != tilepath {

      if tilestep>0 {
        can_overwrite[prev_sfxtag] = true
      }

      prev_pfxtag = ""
      prev_sfxtag = ""

      //fmt.Printf("######\n")
    }

    if tilestep>0 {
      prev_pfxtag = pfxtag
    }

    prev_sglf_info = sglf_info
    prev_tilepath = tilepath

    //fmt.Printf("%d: %x.%x %s (%s) %s (%s)\n", line_no, tilepath, tilestep, prev_pfxtag, pfxtag, prev_sfxtag, sfxtag)

    //fmt.Printf(":%s:\n", l)
    //os.Exit(0)
  }

  return sglf, nil
}

/*
func main() {

  sglf,e := LoadGenomeLibraryCSV("./247_2c5.csv")
  if e!=nil { log.Fatal(e) }

  for path := range sglf.Lib {
    for step := range sglf.Lib[path] {
      for idx:=0; idx<len(sglf.Lib[path][step]); idx++ {
        fmt.Printf("%04x.%04x.%03x %s\n", path, step, idx, sglf.Lib[path][step][idx])
      }
    }
  }

  fmt.Printf("\n\n")

  for m5 := range sglf.MD5Lookup {
    fmt.Printf("%s %04x.%04x.%03x+%x\n", m5,
      sglf.MD5Lookup[m5].Path,
      sglf.MD5Lookup[m5].Step,
      sglf.MD5Lookup[m5].Variant,
      sglf.MD5Lookup[m5].Span)
  }

  fmt.Printf("\n\n")

  for pfxtag := range sglf.PfxTagLookup {
    fmt.Printf("<%s %04x.%04x.%03x+%x\n", pfxtag,
      sglf.PfxTagLookup[pfxtag].Path,
      sglf.PfxTagLookup[pfxtag].Step,
      sglf.PfxTagLookup[pfxtag].Variant,
      sglf.PfxTagLookup[pfxtag].Span)
  }

  fmt.Printf("\n\n")

  for sfxtag := range sglf.SfxTagLookup {
    fmt.Printf(">%s %04x.%04x.%03x+%x\n", sfxtag,
      sglf.SfxTagLookup[sfxtag].Path,
      sglf.SfxTagLookup[sfxtag].Step,
      sglf.SfxTagLookup[sfxtag].Variant,
      sglf.SfxTagLookup[sfxtag].Span)
  }

}
*/
